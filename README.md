
<p align="center">
  <img alt="logo" src="https://raw.githubusercontent.com/axelmierczuk/tenrec/refs/heads/main/tenrec/documentation/static/_media/icon.svg" width="30%" height="30%">
</p>

# Tenrec Capa Plugin

[![PyPI](https://img.shields.io/pypi/v/tenrec-capa)](https://pypi.org/project/tenrec-capa/)
[![Python Version](https://img.shields.io/pypi/pyversions/tenrec-capa)](https://pypi.org/project/tenrec-capa/)
[![License](https://img.shields.io/pypi/l/tenrec-capa)](https://img.shields.io/pypi/l/tenrec-capa)

This plugin integrates [flare-capa](https://github.com/mandiant/capa) with tenrec, 
allowing LLMs to analyze and extract capabilities present in an IDA session.

## Installation

To install the plugin, run:

```bash
tenrec plugins add -p tenrec-capa
```

## Usage

This package exports the `capa` plugin, which can be used to analyze binary files and extract capabilities. 
There are four new operations that tenrec-capa provides:

- `capa_run_analysis`
- `capa_get_capabilities_found`
- `capa_get_capability_results`
- `capa_get_function_results`

For a complete breakdown of the plugin and its operations, 
check out the [documentation](https://axelmierczuk.github.io/tenrec-capa/#/).

