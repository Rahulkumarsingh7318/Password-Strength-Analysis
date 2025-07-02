# Password-Strength-Analysis

import tkinter as tk
from tkinter import ttk, messagebox
import re
from typing import Tuple

class PasswordStrengthAnalyzer:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password Strength Analyzer")
        self.root.geometry("500x450")
        self.root.resizable(False, False)
        
        self.setup_ui()
        self.root.mainloop()
    
    def setup_ui(self):
        # Header Frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(pady=10)
        
        title_label = ttk.Label(
            header_frame,
            text="Password Strength Analyzer",
            font=("Helvetica", 16, "bold")
        )
        title_label.pack()
        
        # Input Frame
        input_frame = ttk.Frame(self.root)
        input_frame.pack(pady=20)
        
        self.password_var = tk.StringVar()
        self.password_var.trace("w", self.update_strength)
        
        password_label = ttk.Label(input_frame, text="Enter Password:")
        password_label.grid(row=0, column=0, sticky=tk.W)
        
        password_entry = ttk.Entry(
            input_frame,
            textvariable=self.password_var,
            width=30,
            show="•"
        )
        password_entry.grid(row=0, column=1, padx=5)
        
        show_password_var = tk.IntVar()
        show_password = ttk.Checkbutton(
            input_frame,
            text="Show password",
            variable=show_password_var,
            command=lambda: self.toggle_password_visibility(password_entry, show_password_var)
        )
        show_password.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Assessment Frame
        assessment_frame = ttk.LabelFrame(self.root, text="Password Assessment")
        assessment_frame.pack(fill=tk.X, padx=10)
        
        self.strength_var = tk.StringVar(value="Not evaluated")
        strength_label = ttk.Label(
            assessment_frame,
            textvariable=self.strength_var,
            font=("Helvetica", 10)
        )
        strength_label.pack(pady=5)
        
        self.score_var = tk.StringVar()
        score_label = ttk.Label(
            assessment_frame,
            textvariable=self.score_var,
            font=("Helvetica", 10)
        )
        score_label.pack(pady=5)
        
        # Criteria Frame
        criteria_frame = ttk.LabelFrame(self.root, text="Strength Criteria")
        criteria_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.length_var = tk.BooleanVar()
        ttk.Checkbutton(
            criteria_frame,
            text="Minimum 8 characters",
            variable=self.length_var,
            state="disabled"
        ).pack(anchor=tk.W)
        
        self.lower_var = tk.BooleanVar()
        ttk.Checkbutton(
            criteria_frame,
            text="Contains lowercase letters",
            variable=self.lower_var,
            state="disabled"
        ).pack(anchor=tk.W)
        
        self.upper_var = tk.BooleanVar()
        ttk.Checkbutton(
            criteria_frame,
            text="Contains uppercase letters",
            variable=self.upper_var,
            state="disabled"
        ).pack(anchor=tk.W)
        
        self.digit_var = tk.BooleanVar()
        ttk.Checkbutton(
            criteria_frame,
            text="Contains digits",
            variable=self.digit_var,
            state="disabled"
        ).pack(anchor=tk.W)
        
        self.special_var = tk.BooleanVar()
        ttk.Checkbutton(
            criteria_frame,
            text="Contains special characters (!@#$%^&*)",
            variable=self.special_var,
            state="disabled"
        ).pack(anchor=tk.W)
        
        # Recommendations Button
        ttk.Button(
            self.root,
            text="View Recommendations",
            command=self.show_recommendations
        ).pack(pady=10)
    
    def toggle_password_visibility(self, entry: ttk.Entry, show_var: tk.IntVar):
        """Toggle password visibility"""
        entry.config(show="" if show_var.get() else "•")
    
    def update_strength(self, *args):
        """Update password strength based on current input"""
        password = self.password_var.get()
        
        if not password:
            self.reset_assessment()
            return
        
        strength, score, criteria = self.evaluate_password(password)
        
        # Update assessment display
        self.strength_var.set(f"Strength: {strength}")
        
        # Set color based on strength
        if strength == "Weak":
            color = "red"
        elif strength == "Moderate":
            color = "orange"
        else:
            color = "green"
        
        self.score_var.set(f"Score: {score}/5")
        self.score_var._root.children["!label"].config(foreground=color)
        
        # Update criteria checkboxes
        self.length_var.set(criteria["length"])
        self.lower_var.set(criteria["lower"])
        self.upper_var.set(criteria["upper"])
        self.digit_var.set(criteria["digit"])
        self.special_var.set(criteria["special"])
    
    def reset_assessment(self):
        """Reset assessment display when no password is entered"""
        self.strength_var.set("Strength: Not evaluated")
        self.score_var.set("")
        
        for var in [self.length_var, self.lower_var, self.upper_var, 
                   self.digit_var, self.special_var]:
            var.set(False)
    
    @staticmethod
    def evaluate_password(password: str) -> Tuple[str, int, dict]:
        """Evaluate password strength and return assessment"""
        criteria = {
            "length": len(password) >= 8,
            "lower": re.search(r'[a-z]', password) is not None,
            "upper": re.search(r'[A-Z]', password) is not None,
            "digit": re.search(r'\d', password) is not None,
            "special": re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None
        }
        
        score = sum(criteria.values())
        
        if score < 3:
            strength = "Weak"
        elif score == 3:
            strength = "Moderate"
        else:
            strength = "Strong"
        
        return strength, score, criteria
    
    def show_recommendations(self):
        """Display password recommendations in a message box"""
        recommendations = [
            "✔️ Use at least 12 characters",
            "✔️ Include both uppercase and lowercase letters",
            "✔️ Add numbers and special characters",
            "✔️ Avoid common words and personal information",
            "✔️ Don't use sequential characters (e.g., '1234')",
            "✔️ Consider using passphrases instead of passwords",
            "✔️ Never reuse passwords across different sites",
            "✔️ Use a password manager to generate and store passwords"
        ]
        
        password = self.password_var.get()
        if password:
            strength, _, _ = self.evaluate_password(password)
            title = f"Recommendations for {strength.lower()} password"
        else:
            title = "General Password Recommendations"
        
        messagebox.showinfo(
            title=title,
            message="\n\n".join(recommendations)
        )

if __name__ == "__main__":
    PasswordStrengthAnalyzer()
