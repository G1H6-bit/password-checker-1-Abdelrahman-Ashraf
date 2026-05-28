import tkinter as tk
from tkinter import font as tkfont
import re

# list of bad passwords that hackers try first
COMMON_WEAK_PASSWORDS = [
    "password", "123456", "123456789", "admin", "qwerty",
    "abc123", "letmein", "welcome", "iloveyou", "monkey",
    "1234", "12345", "111111", "password1", "sunshine",
]


# this function checks the password and gives it a score
def check_password_strength(password):

    score = 0

    # i use a dict to track what the password has and what it doesnt
    checks = {
        "length_good":   False,
        "has_uppercase": False,
        "has_lowercase": False,
        "has_digit":     False,
        "has_symbol":    False,
    }

    # check length first
    length = len(password)
    if length >= 6:
        checks["length_good"] = True
        score += 1

    # uppercase
    if re.search(r"[A-Z]", password):
        checks["has_uppercase"] = True
        score += 1

    # lowercase
    if re.search(r"[a-z]", password):
        checks["has_lowercase"] = True
        score += 1

    # numbers
    if re.search(r"[0-9]", password):
        checks["has_digit"] = True
        score += 1

    # special characters like ! @ # $
    if re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:',.<>?/`~\\\"']", password):
        checks["has_symbol"] = True
        score += 1

    # decide the strength based on score
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    # check if its a common password
    is_common = password.lower() in COMMON_WEAK_PASSWORDS

    # build suggestions for the user
    suggestions = []

    if length < 10:
        suggestions.append("📏 Make it longer, at least 10 characters")
    if not checks["has_uppercase"]:
        suggestions.append("🔠 Add uppercase letters like A B C")
    if not checks["has_lowercase"]:
        suggestions.append("🔡 Add lowercase letters like a b c")
    if not checks["has_digit"]:
        suggestions.append("🔢 Add some numbers")
    if not checks["has_symbol"]:
        suggestions.append("🔣 Add a symbol like ! @ # $")
    if is_common:
        suggestions.insert(0, "🚫 This password is too common, change it")
    if not suggestions:
        suggestions.append("✅ Good password! All checks passed")

    return {
        "score":       score,
        "strength":    strength,
        "is_common":   is_common,
        "checks":      checks,
        "suggestions": suggestions,
    }


# runs when user clicks the check button
def on_check_password():
    password = password_entry.get().strip()

    # dont do anything if the field is empty
    if not password:
        result_label.config(text="⚠️ Please enter a password first.", fg="#FF6B6B")
        strength_label.config(text="")
        warning_label.config(text="")
        suggestions_label.config(text="")
        score_label.config(text="")
        return

    result   = check_password_strength(password)
    strength = result["strength"]
    score    = result["score"]
    is_common = result["is_common"]
    checks   = result["checks"]
    suggestions = result["suggestions"]

    # color changes depending on the result
    colors = {
        "Weak":   "#FF4C4C",
        "Medium": "#FFA500",
        "Strong": "#4CAF50",
    }
    color = colors[strength]

    result_label.config(text=f"Password Strength: {strength}", fg=color)
    score_label.config(text=f"Score: {score} / 5", fg=color)

    # show which checks passed or failed
    lines = []
    lines.append("✔ Length"    if checks["length_good"]   else "✘ Too Short")
    lines.append("✔ Uppercase" if checks["has_uppercase"] else "✘ No Uppercase")
    lines.append("✔ Lowercase" if checks["has_lowercase"] else "✘ No Lowercase")
    lines.append("✔ Numbers"   if checks["has_digit"]     else "✘ No Numbers")
    lines.append("✔ Symbols"   if checks["has_symbol"]    else "✘ No Symbols")
    strength_label.config(text="   |   ".join(lines), fg="#AAAAAA")

    # warn if its a common password
    if is_common:
        warning_label.config(text="⚠️ This is a known leaked password!", fg="#FF4C4C")
    else:
        warning_label.config(text="")

    suggestions_label.config(text="\n".join(suggestions), fg="#CCCCCC")


# clears everything back to empty
def on_clear():
    password_entry.delete(0, tk.END)
    result_label.config(text="", fg="#FFFFFF")
    strength_label.config(text="")
    warning_label.config(text="")
    suggestions_label.config(text="")
    score_label.config(text="")
    password_entry.focus()


# toggle between showing and hiding the password
def toggle_visibility():
    if show_btn["text"] == "👁 Show":
        password_entry.config(show="")
        show_btn.config(text="🙈 Hide")
    else:
        password_entry.config(show="*")
        show_btn.config(text="👁 Show")


# ---- build the window ----

root = tk.Tk()
root.title("Password Strength Checker")
root.configure(bg="#1A1A2E")
root.resizable(False, False)

# center the window on screen
w, h = 750, 620
root.geometry(f"{w}x{h}+{(root.winfo_screenwidth()-w)//2}+{(root.winfo_screenheight()-h)//2}")

# fonts
title_font   = tkfont.Font(family="Segoe UI", size=18, weight="bold")
sub_font     = tkfont.Font(family="Segoe UI", size=10)
label_font   = tkfont.Font(family="Segoe UI", size=11)
btn_font     = tkfont.Font(family="Segoe UI", size=11, weight="bold")
entry_font   = tkfont.Font(family="Consolas",  size=13)
result_font  = tkfont.Font(family="Segoe UI", size=14, weight="bold")
small_font   = tkfont.Font(family="Segoe UI", size=9)
checks_font  = tkfont.Font(family="Consolas",  size=9)

# top bar decoration
tk.Frame(root, bg="#0F3460", height=6).pack(fill="x")

# title
tk.Label(root, text="🛡️  Password Strength Checker",
         font=title_font, bg="#1A1A2E", fg="#E94560").pack(pady=(20, 4))

tk.Label(root, text="Check how strong your password is based on security rules",
         font=sub_font, bg="#1A1A2E", fg="#8888AA").pack(pady=(0, 18))

tk.Frame(root, bg="#0F3460", height=2, width=680).pack(pady=(0, 20))

# input label
tk.Label(root, text="Enter Your Password:", font=label_font,
         bg="#1A1A2E", fg="#CCCCDD").pack(anchor="w", padx=60)

# input area — entry + show button side by side
entry_frame = tk.Frame(root, bg="#1A1A2E")
entry_frame.pack(pady=(6, 4), padx=60, fill="x")

password_entry = tk.Entry(entry_frame, show="*", font=entry_font,
                          bg="#0F3460", fg="#FFFFFF",
                          insertbackground="#E94560",
                          relief="flat", bd=8, width=32)
password_entry.pack(side="left", ipady=6, fill="x", expand=True)
password_entry.focus()

show_btn = tk.Button(entry_frame, text="👁 Show", font=small_font,
                     bg="#0F3460", fg="#8888AA",
                     activebackground="#16213E", activeforeground="#E94560",
                     relief="flat", bd=0, cursor="hand2",
                     command=toggle_visibility)
show_btn.pack(side="left", padx=(6, 0))

# small tip under the input
tk.Label(root, text="💡 Strong passwords use uppercase, lowercase, numbers and symbols",
         font=small_font, bg="#1A1A2E", fg="#555577").pack(pady=(2, 14))

# buttons
buttons_frame = tk.Frame(root, bg="#1A1A2E")
buttons_frame.pack(pady=(0, 18))

tk.Button(buttons_frame, text="🔍  Check Password", font=btn_font,
          bg="#E94560", fg="#FFFFFF",
          activebackground="#C73652", activeforeground="#FFFFFF",
          relief="flat", padx=22, pady=10, cursor="hand2",
          command=on_check_password).pack(side="left", padx=12)

tk.Button(buttons_frame, text="🗑️  Clear", font=btn_font,
          bg="#0F3460", fg="#AAAACC",
          activebackground="#16213E", activeforeground="#FFFFFF",
          relief="flat", padx=22, pady=10, cursor="hand2",
          command=on_clear).pack(side="left", padx=12)

# results area
tk.Frame(root, bg="#0F3460", height=2, width=680).pack(pady=(4, 14))

result_label = tk.Label(root, text="", font=result_font, bg="#1A1A2E", fg="#FFFFFF")
result_label.pack(pady=(0, 4))

score_label = tk.Label(root, text="", font=label_font, bg="#1A1A2E", fg="#FFFFFF")
score_label.pack(pady=(0, 8))

strength_label = tk.Label(root, text="", font=checks_font,
                           bg="#1A1A2E", fg="#AAAAAA", wraplength=680)
strength_label.pack(pady=(0, 8))

warning_label = tk.Label(root, text="", font=label_font,
                          bg="#1A1A2E", fg="#FF4C4C", wraplength=680)
warning_label.pack(pady=(0, 10))

suggestions_label = tk.Label(root, text="", font=small_font,
                               bg="#1A1A2E", fg="#CCCCCC",
                               justify="left", wraplength=680)
suggestions_label.pack(pady=(0, 10))

# footer
tk.Frame(root, bg="#0F3460", height=3).pack(side="bottom", fill="x")
tk.Label(root, text="🔐  Built by Abdelrahman Ashraf  |  Beginner Python & Cybersecurity Project",
         font=small_font, bg="#1A1A2E", fg="#444466").pack(side="bottom", pady=6)

# press enter to check
root.bind("<Return>", lambda event: on_check_password())

root.mainloop()
