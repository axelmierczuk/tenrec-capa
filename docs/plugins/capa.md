# Capa

Plugin to integrate the capa framework for static analysis of binaries.

## Purpose
Perform static analysis on binaries to identify capabilities using the capa framework.

## Interaction Style
- Start by running an analysis on the currently loaded binary using `capa_run_analysis()`.
- Once the analysis is complete, retrieve the list of identified capabilities with `capa_get_capabilities_found()`.
- For detailed results of a specific capability, use `capa_get_capability_results(capability='capability_name')`.
- To see which functions were identified and their associated capabilities, use `capa_get_function_results()`.
- There is likely to be a lot of data, so use pagination options to limit the output.
- There is likely to be a lot of data that is not relevant to your analysis.
- Focus on capabilities and functions that are relevant to your analysis goals.
- Always ensure that the analysis has been run before attempting to retrieve results.

## Examples
- Capa find a complex function with lots of capabilities. This may be an interesting function to analyze.
- Capa found a function that has network capabilities. You should look at this function to see what it does with the network if relevant to your analysis.

## Anti-Examples
- You attempt to analyze the functions with capabilities that are not relevant to your analysis.
- You try to get results before running the analysis.




## Tools

### capa_get_capabilities_found

```function
def capa_get_capabilities_found(offset: int = 0, limit: int = 100) -> list[dict]:
```
Retrieve the capabilities identified in the last capa analysis.

**Args:**
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[dict]</span>**: A list of capability names.


### capa_get_capability_results

```function
def capa_get_capability_results(
    capability: str,
    offset: int = 0,
    limit: int = 100
) -> list[tenrec_capa.plugins.models.MatchResults]:
```
Retrieve the results for a specific capability identified in the last capa analysis.

**Args:**
- **<span class='parameter'>capability</span>** (**<span class='return-type'>str</span>**)
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec_capa.plugins.models.MatchResults]</span>**: A list of results for the specified capability.


### capa_get_function_results

```function
def capa_get_function_results(
    offset: int = 0,
    limit: int = 100
) -> list[tenrec_capa.plugins.models.FunctionResults]:
```
Retrieve the functions identified in the last capa analysis along with their capability counts.

**Args:**
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec_capa.plugins.models.FunctionResults]</span>**: A list of functions with their corresponding result counts.


### capa_run_analysis

```function
def capa_run_analysis() -> dict:
```
Perform capa analysis on the currently loaded binary in the IDA database.

**Returns:**
- **<span class='return-type'>dict</span>**: A message indicating the result of the analysis.
