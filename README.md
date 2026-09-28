IQRA GROUP OF LABORATORY - Advanced LIMS

Port: 5150

Demo mode:
- Default login: admin / admin123
- Use Admin Dashboard -> Lab Settings -> Go Live when ready for production.
- Go Live permanently clears demo patient/order/sample/result/report/billing/inventory-transaction data while retaining master configuration, users, roles, tests, doctors and departments.

Multi-system LAN:
1. Run START.bat on the server PC.
2. Allow TCP port 5150 through Windows Firewall.
3. On other PCs open http://SERVER-PC-IP:5150
4. All workstations use the same server database.

Workflow controls:
- Patient list is visible during New Registration / Order; search by MR#, mobile, name or CNIC.
- Registered patients can be edited by authorized users.
- Orders/invoices can be modified before sample reception when no result has been entered.
- After sample reception, cancellation only.
- After result entry/report processing, order changes are locked.

## HR / Employees
Admin can open **HR / Employees** to maintain a separate staff directory for consultants and laboratory employees. HR records are intentionally separate from application login users and roles. Each record supports employee code, name, type, designation, department, qualification, CNIC, mobile, email, joining date, status and notes. Employees can be Active, On Leave or Inactive. If an employee needs a system login, create the login separately in User Management.


## Accounts Module

The **Accounts** module is a separate financial dashboard and does not add profit/loss figures to the main laboratory dashboard. It provides:

- Daily, monthly, yearly, all-time and custom-date reporting
- Income received from actual patient payments
- Total billed amount for the selected period
- Recorded expenses and expense register
- Profit / Loss = payments received minus recorded expenses
- Expense categories, payment methods, vendors/payees and notes
- Add, edit and delete expense records (with audit logging)
- Separate accounts access permissions: `accounts.view` and `accounts.manage`

For a clean live setup, use **Admin → Lab Settings → Go Live**. The go-live reset also clears expense records.

## Accounts Module
Accounts is a separate financial workspace and does not add profit/loss or expenses to the main laboratory dashboard.

Features:
- Payments received / income register
- Total billed reference
- Expense register with add, edit and delete
- Expense categories and payment methods
- Daily, monthly, yearly, all-time and custom date range views
- Net Profit / Loss = actual payments received minus recorded expenses
- Profit & Loss statement view
- Printable accounts statement
- Granular `accounts.view` and `accounts.manage` permissions
- Financial changes are written to the audit trail
