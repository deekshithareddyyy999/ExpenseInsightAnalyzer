import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sqlite3
from datetime import datetime

# ---------- DATABASE SETUP ----------
conn = sqlite3.connect("expenses.db", check_same_thread=False)
cursor = conn.cursor()

# Create users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
)
''')

# Create expenses table
cursor.execute('''
CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    date TEXT,
    category TEXT,
    amount REAL,
    description TEXT,
    FOREIGN KEY(username) REFERENCES users(username)
)
''')
conn.commit()

# ---------- AUTH FUNCTIONS ----------
def add_user(username, password):
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def validate_user(username, password):
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    return cursor.fetchone() is not None

# ---------- EXPENSE FUNCTIONS ----------
def add_expense_to_db(username, date, category, amount, description):
    cursor.execute(
        "INSERT INTO expenses (username, date, category, amount, description) VALUES (?, ?, ?, ?, ?)",
        (username, date, category, amount, description)
    )
    conn.commit()

def get_expenses_from_db(username):
    cursor.execute(
        "SELECT date, category, amount, description FROM expenses WHERE username=? ORDER BY date DESC",
        (username,)
    )
    rows = cursor.fetchall()
    if rows:
        return pd.DataFrame(rows, columns=["Date", "Category", "Amount", "Description"])
    else:
        return pd.DataFrame(columns=["Date", "Category", "Amount", "Description"])

def load_expenses_from_csv(username, uploaded_file):
    try:
        df = pd.read_csv(uploaded_file)
        # Insert all rows to DB for this user
        for _, row in df.iterrows():
            add_expense_to_db(
                username,
                row.get('Date', datetime.now().strftime("%Y-%m-%d")),
                row.get('Category', 'Other'),
                float(row.get('Amount', 0)),
                row.get('Description', '')
            )
        st.success("CSV data loaded into your expenses!")
    except Exception as e:
        st.error(f"Failed to load CSV: {e}")

# ---------- LOGIN SYSTEM ----------
def login():
    st.title("Login to Expense Insight Analyzer")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if validate_user(username, password):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.success(f"Welcome back, {username}!")
            # Replace st.experimental_rerun() with this:
            st.session_state['login_refresh'] = not st.session_state.get('login_refresh', False)
            st.stop()
        else:
            st.error("Invalid username or password")

    st.write("---")
    st.subheader("New user? Register here:")
    new_username = st.text_input("New Username", key="new_user")
    new_password = st.text_input("New Password", type="password", key="new_pass")
    if st.button("Register"):
        if new_username and new_password:
            if add_user(new_username, new_password):
                st.success("User registered! Please login now.")
            else:
                st.error("Username already taken.")
        else:
            st.error("Please enter username and password.")

def logout():
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        # Replace st.experimental_rerun() with this:
        st.session_state['login_refresh'] = not st.session_state.get('login_refresh', False)
        st.stop()

# ---------- EXPENSE APP ----------
def expense_app():
    st.title(f"Expense Insight Analyzer - User: {st.session_state.username}")

    # Budget Setup
    budget = st.sidebar.number_input("Set your budget", min_value=0.0, format="%.2f")

    # Upload CSV
    st.header("Load Expenses from CSV")
    uploaded_file = st.file_uploader("Upload any CSV file", type=['csv'])
    if uploaded_file is not None:
        load_expenses_from_csv(st.session_state.username, uploaded_file)

    # Add New Expense
    st.sidebar.header("Add a New Expense")
    date = st.sidebar.date_input("Date")
    category = st.sidebar.text_input("Category")
    amount = st.sidebar.number_input("Amount", min_value=0.0, format="%.2f")
    description = st.sidebar.text_input("Description")
    if st.sidebar.button("Add Expense"):
        add_expense_to_db(st.session_state.username, date.strftime("%Y-%m-%d"), category, amount, description)
        st.success("Expense added!")

    # Show Expenses
    st.header("Your Expenses")
    expenses_df = get_expenses_from_db(st.session_state.username)
    st.dataframe(expenses_df)

    # Budget warning
    if budget > 0 and not expenses_df.empty:
        total = pd.to_numeric(expenses_df['Amount'], errors='coerce').sum()
        if total > budget:
            st.warning(f"You've exceeded your budget by ₹{total - budget:.2f}!")

    # Save expenses to CSV
    if st.button("Save Expenses to CSV"):
        try:
            expenses_df.to_csv(f"{st.session_state.username}_expenses.csv", index=False)
            st.success(f"Expenses saved to {st.session_state.username}_expenses.csv!")
        except Exception as e:
            st.error(f"Error saving CSV: {e}")

    # Visualization
    st.header("Visualize Your Expenses")
    if st.button("Visualize"):
        if expenses_df.empty:
            st.warning("No data available to visualize!")
        elif 'Category' in expenses_df.columns and 'Amount' in expenses_df.columns:
            df = expenses_df.copy()
            df['Amount'] = pd.to_numeric(df['Amount'], errors='coerce')
            df.dropna(subset=['Amount'], inplace=True)

            fig, ax = plt.subplots(figsize=(8, 5))
            sns.barplot(data=df, x='Category', y='Amount', estimator=sum, ci=None, ax=ax)
            ax.set_title("Total Expenses by Category")
            plt.xticks(rotation=45)
            st.pyplot(fig)
        else:
            st.error("To visualize, your data must include 'Category' and 'Amount' columns.")

    # Logout button
    st.sidebar.write("---")
    logout()

# ---------- MAIN ----------
def main():
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.username = ""

    if st.session_state.logged_in:
        expense_app()
    else:
        login()

if __name__ == "__main__":
    main()
