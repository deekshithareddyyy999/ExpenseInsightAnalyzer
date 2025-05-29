import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Initialize the expense dataframe
if 'expenses' not in st.session_state:
    st.session_state.expenses = pd.DataFrame(columns=['Date', 'Category', 'Amount', 'Description'])

def add_expense(date, category, amount, description):
    new_expense = pd.DataFrame([[date, category, amount, description]], columns=st.session_state.expenses.columns)
    st.session_state.expenses = pd.concat([st.session_state.expenses, new_expense], ignore_index=True)

def load_expenses():
    uploaded_file = st.file_uploader("Choose a file", type=['csv'])
    if uploaded_file is not None:
        # Read the CSV file into a DataFrame
        st.session_state.expenses = pd.read_csv(uploaded_file)
        st.success("File uploaded successfully!")
        st.dataframe(st.session_state.expenses)  # Display the DataFrame

# Initialize session state if it doesn't exist
if 'expenses' not in st.session_state:
    st.session_state.expenses = None

# Call the function to load expenses
load_expenses()

def save_expenses():
    st.session_state.expenses.to_csv('expenses.csv', index=False)
    st.success("Expenses saved successfully!")

def visualize_expenses():
    if not st.session_state.expenses.empty:
        fig, ax = plt.subplots()
        sns.barplot(data=st.session_state.expenses, x='Category', y='Amount', ax=ax)
        plt.xticks(rotation=45)
        st.pyplot(fig)
    else:
        st.warning("No expenses to visualize!")

st.title('Expense Insight Analyzer')

# Budget input
budget = st.sidebar.number_input('Set your budget', min_value=0.0, format="%.2f")

with st.sidebar:
    st.header('Add Expense')
    date = st.date_input('Date')
    category = st.selectbox('Category', ['Food', 'Transport', 'Entertainment', 'Utilities', 'Other'])
    amount = st.number_input('Amount', min_value=0.0, format="%.2f")
    description = st.text_input('Description')
    if st.button('Add'):
        add_expense(date, category, amount, description)
        st.success('Expense added!')

# Check if total expenses exceed budget
if budget > 0:
    total_expenses = st.session_state.expenses['Amount'].sum()
    if total_expenses > budget:
        st.warning(f"Warning: You have exceeded your budget by {total_expenses - budget:.2f}!")

st.header('Expenses')
st.write(st.session_state.expenses)

st.header('Visualization')
if st.button('Visualize Expenses'):
    visualize_expenses()