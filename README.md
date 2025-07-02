# csv2nq

Tool to convert from domain model CSV files to an NQ file.

Usage: `csv2nq.py [-h] -i directory -o filename [-m filename] [-u] [-e] [-v VERSION] [-n NAME]`

```
  -i directory, --input directory
                        Directory containing CSV files for input
  -o filename, --output filename
                        Output NQ filename
```

Optional arguments are:

```
  -h, --help                      show this help message and exit
  -m filename, --mapping filename Output JSON icon-mapping filename
  -l filename, --log filename     Logfile for diagnostic output
  -u, --unfiltered                Causes SSM GUI Misbehaviour and TWA visibility flags to be set to true.
  -e, --expanded                  Add population model support by expanding relevant structures
  -n NAME, --name NAME            Set the domainGraph string (defaults to what is found in DomainModel.csv). '-unexpanded'
                                  will be appended if the domain model supports populations but this is not enabled by
                                  using '-e'.
  -b LABEL, --label LABEL         Set the rdfs:label string (defaults to what is found in DomainModel.csv). '-UNEXPANDED'
                                  will be appended if the domain model supports populations but this is not enabled by
                                  using '-e'.
  -v VERSION, --version VERSION   Set the versionInfo string (defaults to timestamp) '-unfiltered' will be added to
                                  the version string if '-u' is used.
```
