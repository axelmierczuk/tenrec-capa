import shutil
from collections import defaultdict
from copy import deepcopy
from pathlib import Path

import capa.capabilities
import capa.capabilities.common
import capa.ida.helpers
import capa.loader
import capa.render.result_document
import capa.rules
import capa.version
from capa.features.extractors.ida.extractor import IdaFeatureExtractor
from git import Repo
from loguru import logger
from tenrec.plugins.models import (
    FunctionData,
    HexEA,
    Instructions,
    OperationError,
    PaginatedParameter,
    PluginBase,
    operation,
)

import tenrec_capa
from tenrec_capa.plugins.models import CapaResults, FunctionResults, MatchResults


class CapaPlugin(PluginBase):
    """Plugin to integrate the capa framework for static analysis of binaries."""

    name = "capa"
    version = tenrec_capa.__version__

    instructions = Instructions(
        purpose="Perform static analysis on binaries to identify capabilities using the capa framework.",
        interaction_style=[
            "Start by running an analysis on the currently loaded binary using `capa_run_analysis()`.",
            (
                "Once the analysis is complete, retrieve the list of identified capabilities "
                "with `capa_get_capabilities_found()`."
            ),
            (
                "For detailed results of a specific capability, use "
                "`capa_get_capability_results(capability='capability_name')`."
            ),
            (
                "To see which functions were identified and their associated capabilities, "
                "use `capa_get_function_results()`."
            ),
            "There is likely to be a lot of data, so use pagination options to limit the output.",
            "There is likely to be a lot of data that is not relevant to your analysis.",
            "Focus on capabilities and functions that are relevant to your analysis goals.",
            "Always ensure that the analysis has been run before attempting to retrieve results.",
        ],
        examples=[
            "Capa find a complex function with lots of capabilities. This may be an interesting function to analyze.",
            (
                "Capa found a function that has network capabilities. "
                "You should look at this function to see what it does with the network if relevant to your analysis."
            ),
        ],
        anti_examples=[
            "You attempt to analyze the functions with capabilities that are not relevant to your analysis.",
            "You try to get results before running the analysis.",
        ],
    )

    def __init__(self) -> None:
        self._repo = "https://github.com/mandiant/capa-rules.git"
        self._rules_path = Path(__file__).parent.parent.parent / ".rules"
        self._capa_version = capa.version.__version__
        self._installation()
        self._ruleset = None
        self._feature_extractor = None
        self._results: dict[str, CapaResults] = {}

    def _installation(self) -> None:
        if self._rules_path.exists() and self._rules_path.is_dir():
            error = False
            try:
                repo = Repo(self._rules_path)
                repo.git.checkout(f"v{self._capa_version}", force=True)
                head_commit = repo.head.commit
                tags = [t for t in repo.tags if t.commit == head_commit and t.name == f"v{self._capa_version}"]
                if len(tags) != 1:
                    error = True
            except Exception:
                error = True

            if error:
                shutil.rmtree(self._rules_path)
            else:
                return

        if self._rules_path.exists() and self._rules_path.is_file():
            self._rules_path.unlink()

        Repo.clone_from(
            self._repo,
            self._rules_path,
            branch=f"v{self._capa_version}",
        )

    @operation()
    def run_analysis(self) -> dict:
        """Perform capa analysis on the currently loaded binary in the IDA database.

        :return: A message indicating the result of the analysis.
        :raises OperationError: If the analysis fails at any step.
        """
        index = self.database.sha256
        if self._results.get(index, None) is not None:
            msg = "Capa analysis has already been run on this binary."
            raise OperationError(msg)

        if self._ruleset is None:
            try:
                self._ruleset = capa.rules.get_rules([self._rules_path])
            except Exception as e:
                msg = f"Failed to load capa rules: {e}"
                raise OperationError(msg) from e

        if self._feature_extractor is None:
            try:
                self._feature_extractor = IdaFeatureExtractor()
            except Exception as e:
                msg = f"Failed to initialize the feature extractor: {e}"
                raise OperationError(msg) from e

        ruleset = deepcopy(self._ruleset)

        try:
            meta = capa.ida.helpers.collect_metadata([self._rules_path])
        except Exception as e:
            msg = f"Failed to collect metadata from capa rules: {e}"
            raise OperationError(msg) from e

        try:
            capabilities = capa.capabilities.common.find_capabilities(
                ruleset, self._feature_extractor, disable_progress=True
            )
        except Exception as e:
            msg = f"Failed to analyze the binary with capa: {e}"
            raise OperationError(msg) from e

        try:
            meta.analysis.feature_counts = capabilities.feature_counts
            meta.analysis.library_functions = capabilities.library_functions
        except Exception as e:
            msg = f"Failed to set analysis metadata: {e}"
            raise OperationError(msg) from e

        try:
            meta.analysis.layout = capa.loader.compute_layout(ruleset, self._feature_extractor, capabilities.matches)
        except Exception as e:
            msg = f"Failed to compute analysis layout: {e}"
            raise OperationError(msg) from e

        results = defaultdict(list)
        addresses_found = defaultdict(set)
        total_finds = 0

        for capability, matches in capabilities.matches.items():
            standardized_capability = self._standardize_capability(capability)
            # Process each match for the capability
            for match in matches:
                if len(match) == 0:
                    # Probably shouldn't happen?
                    continue

                # Parse the address. If we can't, skip this match. It's not going to be useful anyways
                try:
                    address = self._convert_absolute_address(str(match[0]))
                except OperationError:
                    logger.warning("Failed to convert address: {}", str(match[0]))
                    continue

                # Make sure we're not duplicating addresses for the same capability
                if address.ea_t in addresses_found[standardized_capability]:
                    continue
                addresses_found[standardized_capability].add(address.ea_t)
                total_finds += 1

                match_data = {"address": address}
                function = self.database.functions.get_at(address.ea_t)
                if function is not None:
                    # Add function data if available
                    match_data["function"] = FunctionData.from_func_t(function)

                results[standardized_capability].append(MatchResults(**match_data))

        self._results[index] = CapaResults(matches=results, meta=meta)
        return {
            "success": True,
            "total_capabilities": len(results),
            "total_finds": total_finds,
            "total_functions": len(capabilities.feature_counts.functions),
        }

    @operation(options=[PaginatedParameter()])
    def get_capabilities_found(self) -> list[dict]:
        """Retrieve the capabilities identified in the last capa analysis.

        :return: A list of capability names.
        :raises OperationError: If no analysis has been performed yet.
        """
        index = self.database.sha256
        results = self._results.get(index, None)
        if results is None:
            msg = "No capa results available for the current binary. Please run the analysis first."
            raise OperationError(msg)
        return [{"capability": k, "count": len(v)} for k, v in results.matches.items()]

    @operation(options=[PaginatedParameter()])
    def get_capability_results(self, capability: str) -> list[MatchResults]:
        """Retrieve the results for a specific capability identified in the last capa analysis.

        :return: A list of results for the specified capability.
        :raises OperationError: If no analysis has been performed yet.
        """
        index = self.database.sha256
        results = self._results.get(index, None)
        if results is None:
            msg = "No capa results available for the current binary. Please run the analysis first."
            raise OperationError(msg)
        output = results.matches.get(capability, None)
        if output is None:
            msg = f"No results found for capability: {capability}"
            raise OperationError(msg)
        return output

    @operation(options=[PaginatedParameter()])
    def get_function_results(self) -> list[FunctionResults]:
        """Retrieve the functions identified in the last capa analysis along with their capability counts.

        :return: A list of functions with their corresponding result counts.
        :raises OperationError: If no analysis has been performed yet.
        """
        index = self.database.sha256
        results = self._results.get(index, None)
        if results is None:
            msg = "No capa results available for the current binary. Please run the analysis first."
            raise OperationError(msg)

        function_results = {}

        for capability, matches in results.matches.items():
            for match in matches:
                function = match.function
                if function is None:
                    continue

                function_index = function.start_ea
                data = function_results.get(function_index)
                if data is None:
                    function_results[function_index] = FunctionResults(function=function)

                function_results[function_index].capabilities[capability] += 1
                function_results[function_index].total += 1
        return sorted(function_results.values(), key=lambda x: x.total, reverse=True)

    @staticmethod
    def _convert_absolute_address(address: str) -> HexEA:
        max_split = 2
        split_address = address.split("(")
        if len(split_address) != max_split or split_address[-1][-1] != ")":
            msg = f"Unexpected address format: {address}"
            raise OperationError(msg)
        return HexEA(split_address[-1][:-1])

    @staticmethod
    def _standardize_capability(capability: str) -> str:
        split_cap = capability.split("/")
        return split_cap[0] if len(split_cap) != 1 else capability
