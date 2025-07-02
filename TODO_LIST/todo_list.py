import sys
sys.path.insert(0, "D:/python_modules")

import tkinter as tk
from tkinter import messagebox, ttk
from tkcalendar import DateEntry
from datetime import datetime
import json
import os

FILE = "todo_data.json"

def load_tasks():
    if os.path.exists(FILE):
        with open(FILE, "r") as f:
            return json.load(f)
    return []

def save_tasks(tasks):
    with open(FILE, "w") as f:
        json.dump(tasks, f, indent=4)

class ToDoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("📝 To-Do List Manager")
        self.root.geometry("600x700")
        self.root.resizable(False, False)

        self.tasks = load_tasks()
        self.filtered_tasks = self.tasks.copy()
        self.theme = "light"
        self.filter_mode = "All"
        self.bg_colors = {"light": "#ffffff", "dark": "#2e2e2e"}
        self.fg_colors = {"light": "#000000", "dark": "#ffffff"}

        self.build_ui()
        self.refresh_tasks()

    def build_ui(self):
        self.root.configure(bg=self.bg_colors[self.theme])

        self.title_label = tk.Label(self.root, text="My Tasks", font=("Helvetica", 20, "bold"), bg=self.bg_colors[self.theme], fg=self.fg_colors[self.theme])
        self.title_label.pack(pady=10)

        self.theme_button = tk.Button(self.root, text="🌗 Toggle Theme", command=self.toggle_theme)
        self.theme_button.pack(pady=5)

        # Filter Dropdown
        self.filter_var = tk.StringVar(value="All")
        self.filter_menu = ttk.Combobox(self.root, textvariable=self.filter_var, values=["All", "Pending", "Completed"], state="readonly", width=15)
        self.filter_menu.pack(pady=5)
        self.filter_menu.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())

        self.entry_frame = tk.Frame(self.root, bg=self.bg_colors[self.theme])
        self.entry_frame.pack(pady=5)

        self.task_entry = tk.Entry(self.entry_frame, width=30, font=("Helvetica", 12))
        self.task_entry.grid(row=0, column=0, padx=5)
        self.task_entry.bind("<Return>", lambda event: self.add_task())

        self.priority_var = tk.StringVar(value="Medium")
        self.priority_menu = ttk.Combobox(self.entry_frame, textvariable=self.priority_var, values=["Low", "Medium", "High"], width=8, state="readonly")
        self.priority_menu.grid(row=0, column=1, padx=5)

        self.due_date_picker = DateEntry(self.entry_frame, width=12, date_pattern="yyyy-mm-dd")
        self.due_date_picker.grid(row=0, column=2, padx=5)

        self.add_button = tk.Button(self.root, text="➕ Add Task", command=self.add_task, width=20, bg="#90ee90")
        self.add_button.pack(pady=5)

        self.task_listbox = tk.Listbox(self.root, width=70, height=15, font=("Courier", 10), selectbackground="#aaa")
        self.task_listbox.pack(pady=10)

        self.button_frame = tk.Frame(self.root, bg=self.bg_colors[self.theme])
        self.button_frame.pack()

        self.complete_button = tk.Button(self.button_frame, text="✅ Mark Done/Undone", command=self.toggle_task)
        self.complete_button.grid(row=0, column=0, padx=5)

        self.delete_button = tk.Button(self.button_frame, text="🗑️ Delete Task", command=self.delete_task)
        self.delete_button.grid(row=0, column=1, padx=5)

    def toggle_theme(self):
        self.theme = "dark" if self.theme == "light" else "light"
        self.root.configure(bg=self.bg_colors[self.theme])
        self.title_label.configure(bg=self.bg_colors[self.theme], fg=self.fg_colors[self.theme])
        self.entry_frame.configure(bg=self.bg_colors[self.theme])
        self.button_frame.configure(bg=self.bg_colors[self.theme])
        self.refresh_tasks()

    def refresh_tasks(self):
        self.task_listbox.delete(0, tk.END)
        for task in self.filtered_tasks:
            status = "✅" if task["done"] else "❌"
            priority = task["priority"]
            date = task["due_date"]
            text = f"{status} [{priority}] {task['title']} (Due: {date})"
            self.task_listbox.insert(tk.END, text)

    def apply_filter(self):
        self.filter_mode = self.filter_var.get()
        if self.filter_mode == "All":
            self.filtered_tasks = self.tasks.copy()
        elif self.filter_mode == "Pending":
            self.filtered_tasks = [t for t in self.tasks if not t["done"]]
        elif self.filter_mode == "Completed":
            self.filtered_tasks = [t for t in self.tasks if t["done"]]
        self.refresh_tasks()

    def add_task(self):
        title = self.task_entry.get().strip()
        due_date = self.due_date_picker.get()
        priority = self.priority_var.get()

        if not title:
            messagebox.showwarning("Input Error", "Task title cannot be empty.")
            return

        self.tasks.append({
            "title": title,
            "done": False,
            "priority": priority,
            "due_date": due_date
        })

        self.task_entry.delete(0, tk.END)
        self.apply_filter()
        save_tasks(self.tasks)

    def toggle_task(self):
        selected = self.task_listbox.curselection()
        if selected:
            visible_index = selected[0]
            actual_task = self.filtered_tasks[visible_index]
            for task in self.tasks:
                if task == actual_task:
                    task["done"] = not task["done"]
                    break
            self.apply_filter()
            save_tasks(self.tasks)
        else:
            messagebox.showinfo("Select Task", "Please select a task to toggle.")

    def delete_task(self):
        selected = self.task_listbox.curselection()
        if selected:
            visible_index = selected[0]
            actual_task = self.filtered_tasks[visible_index]
            confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this task?")
            if confirm:
                self.tasks.remove(actual_task)
                self.apply_filter()
                save_tasks(self.tasks)
        else:
            messagebox.showinfo("Select Task", "Please select a task to delete.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ToDoApp(root)
    root.mainloop()
