[comment]: # "Auto-generated SOAR connector documentation"
# Reversinglabs TitaniumCloud v2

Publisher: ReversingLabs  
Connector Version: 1.0.1  
Product Vendor: Reversinglabs  
Product Name: TitaniumCloud  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.5.0  

App integrates with ReversingLabs TitaniumCloud APIs delivering targeted file and malware intelligence for threat identification, analysis, intelligence development, and threat hunting services

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) ReversingLabs, 2023"
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""



### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a TitaniumCloud asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | TitaniumCloud URL
**username** |  required  | string | TitaniumCloud username
**password** |  required  | password | TitaniumCloud password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[yara create ruleset](#action-yara-create-ruleset) - TCA-0303 - Create a new YARA ruleset  
[yara delete ruleset](#action-yara-delete-ruleset) - TCA-0303 - Delete YARA ruleset  
[yara get ruleset info](#action-yara-get-ruleset-info) - TCA-0303 - Get YARA ruleset info  
[yara get ruleset text](#action-yara-get-ruleset-text) - TCA-0303 - Get YARA ruleset text  
[get yara matches](#action-get-yara-matches) - TCA-0303 - Get a recordset of YARA ruleset matches in the specified time range  
[yara retro enable hunt](#action-yara-retro-enable-hunt) - TCA-0319 - Enable YARA retro hunt  
[yara retro start hunt](#action-yara-retro-start-hunt) - TCA-0319 - Start YARA retro hunt for the specified ruleset  
[yara retro check status](#action-yara-retro-check-status) - TCA-0319 - Check the retro hunt status for the specified ruleset  
[yara retro cancel hunt](#action-yara-retro-cancel-hunt) - TCA-0319 - Cancel the retro hunt for the specified ruleset  
[get yara retro matches](#action-get-yara-retro-matches) - TCA-0319 - Get a recordset of YARA ruleset matches in the specified time range  
[imphash similarity](#action-imphash-similarity) - TCA-0302 - Get a a list of all available SHA1 hashes for files sharing the same import hash (imphash)  
[advanced search](#action-advanced-search) - TCA-0320 - Search for hashes using multi-part search criteria  
[av scanners](#action-av-scanners) - TCA-0103 - Retrieve AV Scanner data from TitaniumCloud  
[file reputation](#action-file-reputation) - TCA-0101 - Queries for file reputation info  
[file analysis](#action-file-analysis) - TCA-0104 - Retrieve File Analysis by hash data from TitaniumCloud  
[functional similarity](#action-functional-similarity) - TCA-0301 - Retrieve a list of functionally similar hashes to the provided one  
[url reputation](#action-url-reputation) - TCA-0403 - Queries URL Threat Intelligence  
[analyze url](#action-analyze-url) - TCA-0404 - Analyze a given URL  
[uri statistics](#action-uri-statistics) - TCA-0402 - Retrieve the number of MALICIOUS, SUSPICIOUS and KNOWN files associated with a specific URI  
[uri index](#action-uri-index) - TCA-0401 - Retrieve a list of all available file hashes associated with a given URI  
[submit for dynamic analysis](#action-submit-for-dynamic-analysis) - TCA-0207 - Submit an existing sample for dynamic analysis  
[dynamic analysis results](#action-dynamic-analysis-results) - TCA-0106 - Retrieve dynamic analysis results  
[reanalyze file](#action-reanalyze-file) - TCA-0205 - Reanalyze sample  
[upload file](#action-upload-file) - TCA-0202 - Upload file to TitaniumCloud  
[get file](#action-get-file) - TCA-0201 - Download a sample from TitaniumCloud  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

Validate the asset configuration for connectivity using supplied configuration.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'yara create ruleset'
TCA-0303 - Create a new YARA ruleset

Type: **generic**  
Read only: **False**

TCA-0303 - Create a new YARA ruleset.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ruleset_name** |  required  | YARA ruleset name | string | 
**ruleset_text** |  required  | Stringified YARA ruleset / a Unicode string | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ruleset_name | string |  |  
action_result.parameter.ruleset_text | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'yara delete ruleset'
TCA-0303 - Delete YARA ruleset

Type: **generic**  
Read only: **False**

TCA-0303 - Delete YARA ruleset.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ruleset_name** |  required  | YARA ruleset name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ruleset_name | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'yara get ruleset info'
TCA-0303 - Get YARA ruleset info

Type: **generic**  
Read only: **False**

TCA-0303 - Get information for a specific YARA ruleset or all YARA rulesets in the collection.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ruleset_name** |  optional  | YARA ruleset name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ruleset_name | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'yara get ruleset text'
TCA-0303 - Get YARA ruleset text

Type: **generic**  
Read only: **False**

TCA-0303 - Get the text of a YARA ruleset.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ruleset_name** |  required  | YARA ruleset name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ruleset_name | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'get yara matches'
TCA-0303 - Get a recordset of YARA ruleset matches in the specified time range

Type: **generic**  
Read only: **False**

TCA-0303 - Get a recordset of YARA ruleset matches in the specified time range.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**time_format** |  required  | 'utc' or 'timestamp' | string | 
**time_value** |  required  | 'YYYY-MM-DDThh:mm:ss' or Unix timestamp string | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.time_format | string |  |  
action_result.parameter.time_value | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'yara retro enable hunt'
TCA-0319 - Enable YARA retro hunt

Type: **generic**  
Read only: **False**

TCA-0319 - Enable the retro hunt for the specified ruleset that has been submitted to TitaniumCloud prior to deployment of YARA retro.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ruleset_name** |  required  | YARA ruleset name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ruleset_name | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'yara retro start hunt'
TCA-0319 - Start YARA retro hunt for the specified ruleset

Type: **generic**  
Read only: **False**

TCA-0319 - Start YARA retro hunt for the specified ruleset.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ruleset_name** |  required  | YARA ruleset name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ruleset_name | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'yara retro check status'
TCA-0319 - Check the retro hunt status for the specified ruleset

Type: **generic**  
Read only: **False**

TCA-0319 - Check the retro hunt status for the specified ruleset.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ruleset_name** |  required  | YARA ruleset name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ruleset_name | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'yara retro cancel hunt'
TCA-0319 - Cancel the retro hunt for the specified ruleset

Type: **generic**  
Read only: **False**

TCA-0319 - Cancel the retro hunt for the specified ruleset.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ruleset_name** |  required  | YARA ruleset name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ruleset_name | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'get yara retro matches'
TCA-0319 - Get a recordset of YARA ruleset matches in the specified time range

Type: **generic**  
Read only: **False**

TCA-0319 - Get a recordset of YARA ruleset matches in the specified time range.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**time_format** |  required  | 'utc' or 'timestamp' | string | 
**time_value** |  required  | 'YYYY-MM-DDThh:mm:ss' or Unix timestamp string | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.time_format | string |  |  
action_result.parameter.time_value | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'imphash similarity'
TCA-0302 - Get a a list of all available SHA1 hashes for files sharing the same import hash (imphash)

Type: **generic**  
Read only: **False**

TCA-0302 - Imphash Index provides a list of all available SHA1 hashes for files sharing the same import hash (imphash). An imphash is a hash calculated from a string which contains the libraries imported by a Windows Portable Executable (PE) file.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**imphash** |  required  | Imphash | string | 
**limit** |  optional  | Maximum number of results | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.imphash | string |  |  
action_result.parameter.limit | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'advanced search'
TCA-0320 - Search for hashes using multi-part search criteria

Type: **generic**  
Read only: **False**

TCA-0320 - Search for hashes using multi-part search criteria. Supported criteria include more than 60 keywords, 35 antivirus vendors, 137 sample types and subtypes, and 283 tags that enable creating 510 unique search expressions with support for Boolean operators and case-insensitive wildcard matching. A number of search keywords support relational operators '<=' and '>='.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Advanced Search query | string | 
**limit** |  optional  | Maximum number of results | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.limit | numeric |  |  
action_result.parameter.query | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'av scanners'
TCA-0103 - Retrieve AV Scanner data from TitaniumCloud

Type: **generic**  
Read only: **False**

TCA-0103 - Provides AV vendor cross-reference data for a desired sample from multiple AV scanners.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.hash | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'file reputation'
TCA-0101 - Queries for file reputation info

Type: **investigate**  
Read only: **True**

TCA-0101 - Queries for file reputation info.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash to query | string |  `hash`  `sha256`  `sha1`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.hash | string |  `hash`  `sha256`  `sha1`  `md5`  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'file analysis'
TCA-0104 - Retrieve File Analysis by hash data from TitaniumCloud

Type: **generic**  
Read only: **False**

TCA-0104 - Provides file analysis data on hashes. Metadata can include relevant portions of static analysis, AV scan information, file sources and any related IP/domain information.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.hash | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'functional similarity'
TCA-0301 - Retrieve a list of functionally similar hashes to the provided one

Type: **generic**  
Read only: **False**

TCA-0301 - Provides a list of SHA1 hashes of files that are functionally similar to the provided file (SHA1 hash) at the selected precision level.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash | string | 
**limit** |  optional  | Maximum number of results | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.hash | string |  |  
action_result.parameter.limit | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'url reputation'
TCA-0403 - Queries URL Threat Intelligence

Type: **investigate**  
Read only: **True**

TCA-0403 - Queries URL Threat Intelligence.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.url | string |  `url`  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'analyze url'
TCA-0404 - Analyze a given URL

Type: **investigate**  
Read only: **False**

TCA-0404 - This service allows users to submit a URL for analysis.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to analyze | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.url | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'uri statistics'
TCA-0402 - Retrieve the number of MALICIOUS, SUSPICIOUS and KNOWN files associated with a specific URI

Type: **generic**  
Read only: **False**

TCA-0402 - Provides the number of MALICIOUS, SUSPICIOUS and KNOWN files associated with a specific URI (domain, IP address, email or URL).

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**uri** |  required  | Uri | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.uri | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'uri index'
TCA-0401 - Retrieve a list of all available file hashes associated with a given URI

Type: **generic**  
Read only: **False**

TCA-0401 - Provides a list of all available file hashes associated with a given URI (domain, IP address, email or URL) regardless of file classification.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**uri** |  required  | Desired URI string | string | 
**limit** |  optional  | Maximum number of results | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.limit | numeric |  |  
action_result.parameter.uri | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'submit for dynamic analysis'
TCA-0207 - Submit an existing sample for dynamic analysis

Type: **generic**  
Read only: **False**

TCA-0207 - This service allows users to detonate a file in the ReversingLabs TitaniumCloud sandbox. To submit a file for analysis, it must exist in TitaniumCloud.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sha1** |  required  | Selected sample's SHA-1 hash | string | 
**platform** |  required  | Selected platform on which the analysis will be performed. See TCA-0207 API documentation for available options | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.platform | string |  |  
action_result.parameter.sha1 | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'dynamic analysis results'
TCA-0106 - Retrieve dynamic analysis results

Type: **generic**  
Read only: **False**

TCA-0106 - This service allows users to retrieve dynamic analysis results for a file that was submitted for dynamic analysis.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sha1** |  required  | Selected sample's SHA-1 hash | string | 
**analysis_id** |  optional  | Return only the results of this analysis | string | 
**latest** |  optional  | Return only the latest analysis results | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.analysis_id | string |  |  
action_result.parameter.latest | boolean |  |  
action_result.parameter.sha1 | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'reanalyze file'
TCA-0205 - Reanalyze sample

Type: **generic**  
Read only: **False**

TCA-0205 - This query sends a sample with the requested hash for rescanning.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.hash | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'upload file'
TCA-0202 - Upload file to TitaniumCloud

Type: **generic**  
Read only: **False**

TCA-0202 - Upload file to TitaniumCloud.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** |  required  | Vault ID of file to upload | string |  `vault id` 
**file_name** |  optional  | Filename to use | string |  `file name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.file_name | string |  `file name`  |  
action_result.parameter.vault_id | string |  `pe file`  `pdf`  `flash`  `apk`  `jar`  `doc`  `xls`  `ppt`  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'get file'
TCA-0201 - Download a sample from TitaniumCloud

Type: **investigate**  
Read only: **True**

TCA-0201 - Download a sample from TitaniumCloud and add it to the vault.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash of file/sample to download | string |  `md5`  `sha1`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.hash | string |  `md5`  `sha1`  `sha256`  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  