---
title: "Pimcore: One click, two security vulnerabilities"
date: 2023-05-16
tags:
	- "php"
	- "sqli"
	- "rce"
	- "path traversal"
advisory: false
origin: https://www.sonarsource.com/blog/pimcore-one-click-two-security-vulnerabilities
cves:
	- "CVE-2023-28438"
---
# Introduction
The Pimcore Platform provides software for central management of corporate data. With over 100,000 clients across 56 countries, including some major vendors, it has become a trusted choice for businesses worldwide. Available in both an Enterprise subscription as well as an Open Source Community Edition with a growing community of developers and users.

We make a consistent effort to enhance the technology powering our Clean Code solution by frequently scanning open-source projects and assessing the outcomes. In the case of Pimcore, our engine reported an interesting limited directory traversal vulnerability. After analyzing the finding we found an additional SQL Injection vulnerability in the same endpoint. Leveraging those two vulnerabilities, an admin that clicks on an attacker’s crafted link will execute arbitrary code on the server.

# Pimcore Vulnerabilities Impact
Pimcore versions prior to 10.5.19 are susceptible to both a **path traversal** and an **SQL injection** vulnerability in the `create-csv` endpoint tracked as CVE-2023-28438. The two vulnerabilities can be exploited with a single GET request. Because of this, an attacker can create a malicious link, which can cause the **execution of arbitrary code** when accessed by an admin. 

<iframe width="100%" height="414" src="https://www.youtube.com/embed/7ODgHHyhuqg" title="Demonstration of Pimcore vulnerabilities on a test instance" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

# Technical Details
In this section, we will discuss the technical details of the vulnerabilities and explain how an attacker could combine them to create a one-click exploit that will deploy a web shell on the server.

## Limited Arbitrary File Write and Path Traversal
Scanning Pimcore with SonarCloud uncovered an interesting path traversal issue caused by passing user-controlled data as the filename parameter of `fopen`. You can inspect the finding directly on SonarCloud:

[Try it by yourself on SonarCloud!](https://sonarcloud.io/project/issues?resolved=false&types=VULNERABILITY&id=SonarSourceResearch_pimcore-blogpost&open=AYbwBqEGzBX2hF8LIsrC&_gl=1*h7icnc*_gcl_au*OTE1ODQ0MTAxLjE2OTg1MTM1NzM.*_ga*MTIwOTcxMTcxNi4xNjk4NTEzNTcz*_ga_9JZ0GZ5TC6*MTY5ODU5NTQzMS4yLjEuMTY5ODU5NTQ3Ny4xNC4wLjA.)

The underlined feature is in the admin panel of Pimcore which enables the display of statistical reports on various aspects of the website. An admin can create custom reports, view them directly from the panel, or download the data in CSV format:

<img src="/img/blogs/pimcore/image1.webp" style="width: 100%;"/>

Upon further inspection of the vulnerable function `createCsvAction`, we found out that the user-controlled data is passed through the `admin/reports/custom-report/create-csv` endpoint’s `exportFile` parameter. Although this endpoint is only accessible by admins, it is a GET request endpoint with no CSRF protection, thus manipulating an admin to click on a link is enough.

The value of the `exportFile` parameter is appended to the web root path without prior sanitization, allowing an attacker to control the extension as well as traverse back in the folder path. 

On continued inspection of the code, we can see that the user-controlled path will end up opening a file in “append” mode. Writing the `getData` function’s output to it using `fputcsv`:

```php
public function createCsvAction(Request $request)
   {
       //...
       $filters = $request->get('filter') ? json_decode(urldecode($request->get('filter')), true) : null;
       $drillDownFilters = $request->get('drillDownFilters', null);
       //...
       $result = $adapter->getData($filters, $sort, $dir, $offset * $limit, $limit, $fields, $drillDownFilters);


       if (!($exportFile = $request->get('exportFile'))) {
           $exportFile = PIMCORE_SYSTEM_TEMP_DIRECTORY . '/report-export-' . uniqid() . '.csv';
           @unlink($exportFile);
       } else {
           $exportFile = PIMCORE_SYSTEM_TEMP_DIRECTORY.'/'.$exportFile;
       }


       $fp = fopen($exportFile, 'a');


       if ($includeHeaders) {
           fputcsv($fp, $fields, ';');
       }


       foreach ($result['data'] as $row) {
           $row = Service::escapeCsvRecord($row);
           fputcsv($fp, array_values($row), ';');
       }


       //...
   }
```
[File in Github](https://github.com/pimcore/pimcore/blob/928a964c13a5c9992cff4b5abdb25847529604d3/bundles/CustomReportsBundle/src/Controller/Reports/CustomReportController.php#L422%C2%A0)

Up until now, an attacker can control the CSV output file path, name, and extension. Although this allows the creation of PHP files on the server, an attacker will need to control the file content as well in order to execute arbitrary code. Here enters the second vulnerability, an SQL Injection in the `getData` function.

## 1st SQL Injection sink
Looking at the `createCsvAction` function from earlier, the inputs an attacker can control are `$drillDownFilters` and `$filters`, which are passed on to `getBaseQuery`:

```php
 public function getData($filters, $sort, $dir, $offset, $limit, $fields = null, $drillDownFilters = null)
   {
       $db = Db::get();


       $baseQuery = $this->getBaseQuery($filters, $fields, false, $drillDownFilters);
       //...
       if ($baseQuery) {
           $total = $db->fetchOne($baseQuery['count']);
           //...
           $sql = $baseQuery['data'] . $order;
           //...
           $data = $db->fetchAllAssociative($sql);
      //...
   }
```
[File in Github](https://github.com/pimcore/pimcore/blob/v11.0.0-ALPHA5/bundles/CustomReportsBundle/src/Tool/Adapter/Sql.php#L29)

Two SQL queries are issued with the result of the `getBaseQuery` function:

1. `$baseQuery[‘count’]`: a query that returns the number of results using `COUNT(*)` will be used in `$db->fetchOne`.
2. `$baseQuery[‘data’]`: will end up in `$db->fetchAllAssociative` and fetch the results.

This is how the `getBaseQuery` function that prepares those two queries looks like:
```php
protected function getBaseQuery($filters, $fields, $ignoreSelectAndGroupBy = false, $drillDownFilters = null, $selectField = null)
   {
	//...
       $sql = $this->buildQueryString($this->config, $ignoreSelectAndGroupBy, $drillDownFilters, $selectField);
       //...
               foreach ($filters as $filter) {
                   $operator = $filter['operator'];
                   //..
                   switch ($operator) {
			//..
                       case '=':
                           $fields[] = $filter['property'];
                           $condition[] = $db->quoteIdentifier($filter['property']) . ' = ' . $db->quote($value);
    		//...
           $total = 'SELECT COUNT(*) FROM (' . $sql . ') AS somerandxyz WHERE ' . $condition;
           if ($fields && !$extractAllFields) {
               $data = 'SELECT `' . implode('`,`', $fields) . '` FROM (' . $sql . ') AS somerandxyz WHERE ' . $condition;
           }
		//...
       return [
           'data' => $data,
           'count' => $total,
       ];
   }
```
[File in Github](https://github.com/pimcore/pimcore/blob/v11.0.0-ALPHA5/bundles/CustomReportsBundle/src/Tool/Adapter/Sql.php#L150)

At first glance, we noticed an injection at the `$data` parameter, the SQL query's `SELECT` fields are not sanitized. The ```implode('`,`', $fields)``` can simply be escaped with backticks.

In order to control the `$fields` parameter we need to set the `$filters['operator']` attribute accordingly (in the code snippet only '=' is shown but there are other options) and then the `'property'` attribute will be appended to it. Immediately after a `$condition` string will be created. So in order to control the `$fields` value the `$condition` string will be present. 

However, while it seems like there is a simple SQL injection at `$data`, the `$condition` variable is concatenated to the end of both queries (`count` and `data`). And due to the quotation escaping (done using the functions `$db->quoteIdentifier` and `$db->quote`), any field containing a backtick character (`) will be doubled and thus making the query's syntax invalid.

We can of course comment out the rest of the query (using `--` or `;`) to avoid the syntax breaking `$condition`. But the `$total` query also has the broken `$condition`, and later be used in the line `$db->fetchOne($baseQuery['count'])` before fetching with the SQL Injected `data` query, thus raising an exception and not executing the SQL Injection.

## 2nd SQL Injection sink
So we have an SQL Injection, but exploiting it will always cause a syntax error. Is there any other way to somehow ignore the `$condition` string?

Some of you probably already noticed that before every `$condition` there is the `$sql` parameter, which is returned from `$this->getBaseQuery(...)`. If there is an SQL Injection in that function as well we can end the query before the syntax error.

```php
protected function buildQueryString($config, $ignoreSelectAndGroupBy = false, $drillDownFilters = null, $selectField = null)
   {
       //...
       if ($drillDownFilters) {
           $havingParts = [];
           $db = Db::get();
           foreach ($drillDownFilters as $field => $value) {
               if ($value !== '' && $value !== null) {
                   $havingParts[] = "$field = " . $db->quote($value);
               }
           }


           if ($havingParts) {
               $sql .= ' HAVING ' . implode(' AND ', $havingParts);
           }
       }
       return $sql;
   }
```

Auditing the `buildQueryString` function we found another SQL Injection sink but now using the `$drillDownFilters` parameter. Though the value is being quoted, the field isn't. An attacker can use this sync to comment out the broken `$condition` and execute arbitrary SQL queries.

# Exploitation - connecting everything together
So an attacker can control the output file and inject SQL to the function that fetches results which will end up in that file. Having the export file path pointing to a PHP file in the web root is straightforward using: 

```
../../../../../../../../var/www/html/public/webshell.php
```

A PHP file will execute also if there is the PHP declaration randomly in the file, meaning a file doesn't have to start with `<?php`, so we don't have to worry about that. 

But how can an attacker exploit the SQL Injection to result in arbitrary content?

Having multiple queries, one that inserts custom data and another that fetches it is possible but makes the exploit more complicated. Going back to our SQL query, the injection is in the SELECT fields, so we can use the [CASE expression](https://www.w3schools.com/sql/sql_case.asp).

Lastly, there are two parameters needed for the get request: 

* `headers=true` is to output the field names to the CSV
* `name=Quality_Attributes` is a default name of a report from the demo app (in order to execute the vulnerable function the name has to be a valid report)

Combining those 2 vulnerabilities from 3 sinks in 1 GET request an attacker could create a malicious link that will deploy a web shell on the server.

# Patch
Both vulnerabilities were fixed in Pimcore version 10.5.19:

* The SQL Injection was fixed by adding db->quoteIdentifier(...) in the field name as well.
```php
$havingParts[] = ($db->quoteIdentifier($field) ." = " . $db->quote($value));
```
* The path traversal was fixed by:
	* Verifying that the extension is “.csv”
	* Normalizing the path to prevent traversing 
```php
$exportFileName = basename($exportFileName);
if(!str_ends_with($exportFileName, ".csv")) {
      throw new InvalidArgumentException($exportFileName . " is not a valid csv file.");
}
return PIMCORE_SYSTEM_TEMP_DIRECTORY . '/' . $exportFileName;
```

# Timeline
| Date    | Action |
| -------- | ------- |
| 2023-02-20 | We reported all issues to Vendor |
| 2023-03-15 | Vendor released patch version 10.5.19 |
| 2023-03-22 | CVE-2023-28438 and [security advisory](https://github.com/pimcore/pimcore/security/advisories/GHSA-vf7q-g2pv-jxvx) released |

# Summary
The focus of our blog post was on our success in identifying and utilizing two distinct vulnerabilities with a single GET request, ultimately leading to code execution. This serves as a powerful demonstration of our product's capability to detect security flaws, and we also highlighted the step-by-step process we followed from analyzing the results to creating a weaponized exploit.

We would like to thank the maintainers again for the quick response and for handling the situation professionally.