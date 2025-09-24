import tkinter as tk
from tkinter import ttk
import re
import math
import hashlib

class PasswordStrengthChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker")
        self.root.geometry("600x500")
        self.root.resizable(False, False)
        
        # Common weak passwords for comparison
        self.common_passwords = {
            "password", "123456", "12345678", "1234", "qwerty", "abc123", 
            "password1", "admin", "letmein", "welcome", "monkey", "sunshine",
            "password123", "admin123", "login", "passw0rd", "master", "hello"
        }
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Password Strength Checker", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Password entry
        ttk.Label(main_frame, text="Enter Password:").grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, show="•", width=40)
        self.password_entry.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        self.password_var.trace_add("write", self.check_password_strength)
        
        # Show password checkbox
        self.show_password_var = tk.IntVar()
        show_password_cb = ttk.Checkbutton(main_frame, text="Show password", 
                                          variable=self.show_password_var,
                                          command=self.toggle_password_visibility)
        show_password_cb.grid(row=3, column=0, sticky=tk.W, pady=(0, 20))
        
        # Strength meter
        ttk.Label(main_frame, text="Password Strength:").grid(row=4, column=0, sticky=tk.W, pady=(0, 5))
        self.strength_meter = ttk.Progressbar(main_frame, length=400, mode='determinate')
        self.strength_meter.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Strength label
        self.strength_label = ttk.Label(main_frame, text="", font=("Arial", 12))
        self.strength_label.grid(row=6, column=0, sticky=tk.W, pady=(0, 20))
        
        # Feedback frame
        feedback_frame = ttk.LabelFrame(main_frame, text="Feedback", padding="10")
        feedback_frame.grid(row=7, column=0, sticky=(tk.W, tk.E), pady=(0, 20))
        feedback_frame.columnconfigure(0, weight=1)
        
        self.feedback_text = tk.Text(feedback_frame, height=8, width=50, wrap=tk.WORD)
        self.feedback_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Scrollbar for feedback text
        scrollbar = ttk.Scrollbar(feedback_frame, orient=tk.VERTICAL, command=self.feedback_text.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.feedback_text.config(yscrollcommand=scrollbar.set)
        
        # Additional info
        info_frame = ttk.Frame(main_frame)
        info_frame.grid(row=8, column=0, sticky=(tk.W, tk.E))
        
        ttk.Label(info_frame, text="Password Tips:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W)
        tips = [
            "• Use at least 12 characters",
            "• Include uppercase and lowercase letters",
            "• Add numbers and special characters",
            "• Avoid common words and patterns",
            "• Don't use personal information"
        ]
        
        for i, tip in enumerate(tips, 1):
            ttk.Label(info_frame, text=tip).grid(row=i, column=0, sticky=tk.W)
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        
    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def check_password_strength(self, *args):
        password = self.password_var.get()
        
        if not password:
            self.strength_meter.config(value=0)
            self.strength_label.config(text="")
            self.feedback_text.delete(1.0, tk.END)
            return
        
        # Calculate password strength
        score, feedback = self.calculate_strength(password)
        
        # Update UI
        self.strength_meter.config(value=score)
        
        # Set strength label and color
        if score < 40:
            strength_text = "Very Weak"
            color = "red"
        elif score < 60:
            strength_text = "Weak"
            color = "orange"
        elif score < 80:
            strength_text = "Moderate"
            color = "yellow"
        elif score < 90:
            strength_text = "Strong"
            color = "lightgreen"
        else:
            strength_text = "Very Strong"
            color = "green"
            
        self.strength_label.config(text=strength_text, foreground=color)
        
        # Update feedback
        self.feedback_text.delete(1.0, tk.END)
        for item in feedback:
            self.feedback_text.insert(tk.END, f"• {item}\n")
    
    def calculate_strength(self, password):
        score = 0
        feedback = []
        
        # Length check
        length = len(password)
        if length < 8:
            score += length * 2
            feedback.append("Password is too short (minimum 8 characters)")
        elif length < 12:
            score += length * 3
            feedback.append("Password could be longer (recommended 12+ characters)")
        else:
            score += length * 4
            feedback.append("Good password length")
        
        # Character variety checks
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^A-Za-z0-9]', password))
        
        if has_upper:
            score += 10
            feedback.append("Contains uppercase letters")
        else:
            feedback.append("Add uppercase letters for better security")
            
        if has_lower:
            score += 10
            feedback.append("Contains lowercase letters")
        else:
            feedback.append("Add lowercase letters for better security")
            
        if has_digit:
            score += 10
            feedback.append("Contains numbers")
        else:
            feedback.append("Add numbers for better security")
            
        if has_special:
            score += 15
            feedback.append("Contains special characters")
        else:
            feedback.append("Add special characters (!, @, #, etc.) for better security")
        
        # Check for common passwords
        if password.lower() in self.common_passwords:
            score -= 30
            feedback.append("This is a very common password - choose something more unique")
        
        # Check for sequential characters (e.g., 123, abc)
        sequential_patterns = [
            "012", "123", "234", "345", "456", "567", "678", "789",
            "abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij", 
            "ijk", "jkl", "klm", "lmn", "mno", "nop", "opq", "pqr", 
            "qrs", "rst", "stu", "tuv", "uvw", "vwx", "wxy", "xyz"
        ]
        
        has_sequential = False
        for pattern in sequential_patterns:
            if pattern in password.lower():
                has_sequential = True
                break
                
        if has_sequential:
            score -= 15
            feedback.append("Avoid sequential patterns (e.g., 123, abc)")
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            score -= 10
            feedback.append("Avoid repeated characters (e.g., aaa, 111)")
        
        # Calculate entropy (measure of unpredictability)
        charset_size = 0
        if has_upper:
            charset_size += 26
        if has_lower:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32  # Approximate number of common special chars
            
        if charset_size > 0:
            entropy = length * math.log2(charset_size)
            entropy_score = min(entropy * 2, 30)  # Scale entropy to contribute up to 30 points
            score += entropy_score
            feedback.append(f"High entropy (unpredictability): {entropy:.1f} bits")
        
        # Ensure score is within 0-100 range
        score = max(0, min(100, score))
        
        return score, feedback

def main():
    root = tk.Tk()
    app = PasswordStrengthChecker(root)
    root.mainloop()

if __name__ == "__main__":
    main()