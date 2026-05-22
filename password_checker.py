# -*- coding: utf-8 -*-
# ============================================================
# PROJECT: Cyber Security Password Strength Checker
# AUTHOR:  Beginner Python & Cybersecurity Project
# PURPOSE: Evaluate password strength using security rules
# ============================================================

# --- IMPORT REQUIRED LIBRARIES ---
# tkinter is Python's built-in library for creating GUIs (Graphical User Interfaces)
import tkinter as tk
from tkinter import font as tkfont   # Used to customize text fonts inside the GUI

# --- IMPORT THE 're' MODULE FOR PATTERN MATCHING ---
# 're' stands for Regular Expressions — it helps us search for patterns in text
import re


# ============================================================
# SECTION 1: LIST OF COMMON LEAKED PASSWORDS
# ============================================================
# These passwords appear in millions of real-world data breaches.
# Hackers use "dictionary attacks" — they try these first before anything else.
# If a user picks one of these, we must warn them immediately.
COMMON_WEAK_PASSWORDS = [
    "password",
    "123456",
    "123456789",
    "admin",
    "qwerty",
    "abc123",
    "letmein",
    "welcome",
    "iloveyou",
    "monkey",
    "1234",
    "12345",
    "111111",
    "password1",
    "sunshine",
]


# ============================================================
# SECTION 2: PASSWORD ANALYSIS FUNCTION
# ============================================================
# This function takes a password string as input,
# runs all security checks, and returns a result dictionary.
def check_password_strength(password):
    """
    Analyzes the given password and returns a dictionary with:
    - score       : integer score (0–5+)
    - strength    : "Weak", "Medium", or "Strong"
    - is_common   : True if the password is a known leaked password
    - checks      : dict of which rules the password passed
    - suggestions : list of tips to improve the password
    """

    # Start with a score of zero — we add points for each rule the password passes
    score = 0

    # Dictionary to track which security checks the password passes
    # Each key is a check name, each value is True (pass) or False (fail)
    checks = {
        "length_good":      False,   # Is the password long enough?
        "has_uppercase":    False,   # Does it have at least one capital letter?
        "has_lowercase":    False,   # Does it have at least one small letter?
        "has_digit":        False,   # Does it have at least one number?
        "has_symbol":       False,   # Does it have at least one special character?
    }

    # --- CHECK 1: PASSWORD LENGTH ---
    # WHY: Longer passwords take exponentially longer to crack by brute force.
    # A 6-character password has ~1 billion combinations; 10+ characters are far stronger.
    password_length = len(password)   # Count how many characters are in the password

    if password_length < 6:
        # Very short — automatically considered weak, no length point awarded
        checks["length_good"] = False
    elif password_length >= 6 and password_length <= 9:
        # Medium length — gives 1 point
        checks["length_good"] = True
        score += 1
    else:
        # 10+ characters — strong candidate, gives 1 point
        checks["length_good"] = True
        score += 1

    # --- CHECK 2: UPPERCASE LETTERS ---
    # WHY: Adding uppercase letters multiplies the number of possible combinations
    #      a hacker must try. "hello" is far easier to crack than "Hello".
    if re.search(r"[A-Z]", password):   # re.search looks for any uppercase letter A–Z
        checks["has_uppercase"] = True
        score += 1   # Award 1 point

    # --- CHECK 3: LOWERCASE LETTERS ---
    # WHY: A password made of only uppercase is just as weak as all lowercase.
    #      Mixing cases forces attackers to try more combinations.
    if re.search(r"[a-z]", password):   # Looks for any lowercase letter a–z
        checks["has_lowercase"] = True
        score += 1

    # --- CHECK 4: DIGITS (NUMBERS) ---
    # WHY: Adding numbers increases the character pool.
    #      Without numbers, only 52 possible characters (26 upper + 26 lower).
    #      With numbers, that grows to 62 characters — many more combinations.
    if re.search(r"[0-9]", password):   # Looks for any digit 0–9
        checks["has_digit"] = True
        score += 1

    # --- CHECK 5: SPECIAL SYMBOLS ---
    # WHY: Symbols are the strongest addition to a password.
    #      They push the character pool from 62 to 94+ possible values.
    #      Example: "Pass1" vs "P@ss1!" — the second is exponentially harder to crack.
    symbol_pattern = r"[!@#$%^&*()\-_=+\[\]{}|;:',.<>?/`~\\\"']"
    if re.search(symbol_pattern, password):   # Looks for any symbol
        checks["has_symbol"] = True
        score += 1

    # --- DETERMINE STRENGTH LABEL BASED ON SCORE ---
    # Score 0–2: Weak  →  Can be cracked in seconds with modern tools
    # Score 3–4: Medium → Moderate resistance, but not fully safe
    # Score 5+:  Strong → Excellent resistance against most attacks
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    # --- CHECK IF PASSWORD IS IN THE COMMON LIST ---
    # We compare the lowercase version of the password to catch variations like "PASSWORD"
    is_common = password.lower() in COMMON_WEAK_PASSWORDS

    # --- BUILD SUGGESTIONS LIST ---
    # We give personalized advice for each failed check
    suggestions = []

    if password_length < 10:
        suggestions.append("📏 Increase password length to at least 10 characters")

    if not checks["has_uppercase"]:
        suggestions.append("🔠 Add at least one uppercase letter (e.g., A, B, C...)")

    if not checks["has_lowercase"]:
        suggestions.append("🔡 Add at least one lowercase letter (e.g., a, b, c...)")

    if not checks["has_digit"]:
        suggestions.append("🔢 Add at least one number (e.g., 1, 2, 3...)")

    if not checks["has_symbol"]:
        suggestions.append("🔣 Add a symbol (e.g., !, @, #, $, %, ^, &, *)")

    if is_common:
        suggestions.insert(0, "🚫 Avoid predictable patterns and leaked passwords")

    # If the password is already perfect, give a congratulations message
    if not suggestions:
        suggestions.append("✅ Your password meets all security requirements!")

    # --- RETURN ALL RESULTS AS A DICTIONARY ---
    # A dictionary is like a labeled container — we can access each result by name
    return {
        "score":       score,
        "strength":    strength,
        "is_common":   is_common,
        "checks":      checks,
        "suggestions": suggestions,
    }


# ============================================================
# SECTION 3: GUI FUNCTIONS (Button Actions)
# ============================================================

def on_check_password():
    """
    This function runs when the user clicks 'Check Password'.
    It reads the password from the input field, runs the analysis,
    and updates all the labels in the GUI with the results.
    """

    # Read the current text from the password entry box
    # .strip() removes any accidental spaces at the start or end
    password = password_entry.get().strip()

    # If the entry box is empty, show an error message and stop
    if not password:
        result_label.config(
            text="⚠️ Please enter a password first.",
            fg="#FF6B6B"   # Red color to signal an error
        )
        strength_label.config(text="")
        warning_label.config(text="")
        suggestions_label.config(text="")
        score_label.config(text="")
        return   # Stop here — don't continue if there's no input

    # --- RUN THE PASSWORD ANALYSIS ---
    # Call our analysis function and store all results in 'result'
    result = check_password_strength(password)

    # Extract individual values from the result dictionary
    strength    = result["strength"]
    score       = result["score"]
    is_common   = result["is_common"]
    checks      = result["checks"]
    suggestions = result["suggestions"]

    # --- CHOOSE COLOR BASED ON STRENGTH ---
    # Colors help users visually understand the result at a glance
    strength_colors = {
        "Weak":   "#FF4C4C",   # Red  — danger
        "Medium": "#FFA500",   # Orange — caution
        "Strong": "#4CAF50",   # Green — safe
    }
    strength_color = strength_colors[strength]

    # --- UPDATE THE RESULT LABEL ---
    result_label.config(
        text=f"Password Strength: {strength}",
        fg=strength_color
    )

    # --- UPDATE THE SCORE LABEL ---
    score_label.config(
        text=f"Security Score: {score} / 5 points",
        fg=strength_color
    )

    # --- UPDATE THE CHECKS SUMMARY ---
    # Build a readable summary line for each check
    check_lines = []
    check_lines.append("✔ Length OK" if checks["length_good"] else "✘ Too Short")
    check_lines.append("✔ Uppercase" if checks["has_uppercase"] else "✘ No Uppercase")
    check_lines.append("✔ Lowercase" if checks["has_lowercase"] else "✘ No Lowercase")
    check_lines.append("✔ Numbers"   if checks["has_digit"]     else "✘ No Numbers")
    check_lines.append("✔ Symbols"   if checks["has_symbol"]    else "✘ No Symbols")

    # Join all lines with a separator for display
    strength_label.config(
        text="   |   ".join(check_lines),
        fg="#AAAAAA"
    )

    # --- SHOW WARNING IF COMMON PASSWORD DETECTED ---
    if is_common:
        warning_label.config(
            text="⚠️  Warning: Common leaked password detected! Change it immediately.",
            fg="#FF4C4C"   # Bold red warning
        )
    else:
        warning_label.config(text="")   # Clear any previous warning

    # --- DISPLAY IMPROVEMENT SUGGESTIONS ---
    # Join all suggestion strings with a newline so each appears on its own line
    suggestions_text = "\n".join(suggestions)
    suggestions_label.config(
        text=suggestions_text,
        fg="#CCCCCC"
    )


def on_clear():
    """
    This function runs when the user clicks 'Clear'.
    It resets all fields back to their default empty state.
    """
    password_entry.delete(0, tk.END)   # Delete all text from the entry widget
    result_label.config(text="", fg="#FFFFFF")
    strength_label.config(text="")
    warning_label.config(text="")
    suggestions_label.config(text="")
    score_label.config(text="")
    password_entry.focus()   # Move cursor focus back to the input field


def toggle_password_visibility():
    """
    Toggles the password field between hidden (***) and visible mode.
    This lets users confirm what they typed without exposing it permanently.
    """
    # Check the current state of the show/hide button text
    if show_btn["text"] == "👁 Show":
        password_entry.config(show="")       # Show actual characters
        show_btn.config(text="🙈 Hide")
    else:
        password_entry.config(show="*")      # Mask characters with *
        show_btn.config(text="👁 Show")


# ============================================================
# SECTION 4: BUILD THE GUI WINDOW
# ============================================================

# --- CREATE THE MAIN APPLICATION WINDOW ---
# tk.Tk() is the root window — the base of every tkinter application
root = tk.Tk()

# Set the window title (appears in the title bar)
root.title("Cyber Security Password Strength Checker")

# Set the window background color to a dark cybersecurity theme
root.configure(bg="#1A1A2E")   # Deep navy/dark blue

# --- SET WINDOW SIZE AND CENTER IT ON SCREEN ---
window_width  = 750   # Width of the window in pixels
window_height = 620   # Height of the window in pixels

# Get the screen dimensions (resolution of the monitor)
screen_width  = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Calculate position so the window appears in the center of the screen
# Formula: (screen size - window size) // 2
x_position = (screen_width  - window_width)  // 2
y_position = (screen_height - window_height) // 2

# Apply the window size and position using geometry string "WxH+X+Y"
root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

# Prevent the user from resizing the window (keeps layout clean)
root.resizable(False, False)


# ============================================================
# SECTION 5: DEFINE FONTS
# ============================================================
# We define font styles once and reuse them — cleaner and easier to update

title_font      = tkfont.Font(family="Segoe UI", size=18, weight="bold")
subtitle_font   = tkfont.Font(family="Segoe UI", size=10)
label_font      = tkfont.Font(family="Segoe UI", size=11)
button_font     = tkfont.Font(family="Segoe UI", size=11, weight="bold")
entry_font      = tkfont.Font(family="Consolas",  size=13)   # Monospace for password feel
result_font     = tkfont.Font(family="Segoe UI", size=14, weight="bold")
small_font      = tkfont.Font(family="Segoe UI", size=9)
checks_font     = tkfont.Font(family="Consolas",  size=9)


# ============================================================
# SECTION 6: ADD ALL GUI WIDGETS (Labels, Entries, Buttons)
# ============================================================

# --- HEADER / TITLE AREA ---

# Decorative top bar (simulates a cybersecurity theme)
top_bar = tk.Frame(root, bg="#0F3460", height=6)
top_bar.pack(fill="x")   # Fill the full width of the window

# Shield emoji + main title
title_label = tk.Label(
    root,
    text="🛡️  Password Strength Checker",
    font=title_font,
    bg="#1A1A2E",
    fg="#E94560"   # Cyber red — matches the security theme
)
title_label.pack(pady=(20, 4))   # 20px space above, 4px space below

# Subtitle / description
subtitle_label = tk.Label(
    root,
    text="Evaluate your password security level using cybersecurity rules",
    font=subtitle_font,
    bg="#1A1A2E",
    fg="#8888AA"   # Muted purple-grey for secondary text
)
subtitle_label.pack(pady=(0, 18))

# Horizontal divider line (uses a thin Frame as a visual separator)
divider = tk.Frame(root, bg="#0F3460", height=2, width=680)
divider.pack(pady=(0, 20))

# --- PASSWORD INPUT AREA ---

# Label above the input field
input_label = tk.Label(
    root,
    text="Enter Your Password:",
    font=label_font,
    bg="#1A1A2E",
    fg="#CCCCDD"
)
input_label.pack(anchor="w", padx=60)   # anchor="w" = align to the left (west)

# Frame to hold the password entry + show/hide button side by side
entry_frame = tk.Frame(root, bg="#1A1A2E")
entry_frame.pack(pady=(6, 4), padx=60, fill="x")

# Password Entry widget — show="*" hides the characters with asterisks
password_entry = tk.Entry(
    entry_frame,
    show="*",                # Hide password characters with *
    font=entry_font,
    bg="#0F3460",            # Dark blue background for input
    fg="#FFFFFF",            # White text
    insertbackground="#E94560",  # Red blinking cursor
    relief="flat",           # No 3D border (flat = modern look)
    bd=8,                    # Padding inside the entry box
    width=32
)
password_entry.pack(side="left", ipady=6, fill="x", expand=True)
password_entry.focus()   # Auto-focus so the user can type immediately

# Show/Hide password toggle button
show_btn = tk.Button(
    entry_frame,
    text="👁 Show",
    font=small_font,
    bg="#0F3460",
    fg="#8888AA",
    activebackground="#16213E",
    activeforeground="#E94560",
    relief="flat",
    bd=0,
    cursor="hand2",          # Hand cursor on hover — signals it's clickable
    command=toggle_password_visibility
)
show_btn.pack(side="left", padx=(6, 0))

# --- PASSWORD STRENGTH HINT (under the entry) ---
hint_label = tk.Label(
    root,
    text="💡 Tip: A strong password uses uppercase, lowercase, numbers, and symbols",
    font=small_font,
    bg="#1A1A2E",
    fg="#555577"
)
hint_label.pack(pady=(2, 14))

# --- ACTION BUTTONS ---

# Frame to hold both buttons side by side, centered
buttons_frame = tk.Frame(root, bg="#1A1A2E")
buttons_frame.pack(pady=(0, 18))

# "Check Password" button — triggers the main analysis
check_btn = tk.Button(
    buttons_frame,
    text="🔍  Check Password",
    font=button_font,
    bg="#E94560",            # Cyber red — calls to action
    fg="#FFFFFF",
    activebackground="#C73652",
    activeforeground="#FFFFFF",
    relief="flat",
    padx=22,
    pady=10,
    cursor="hand2",
    command=on_check_password   # Link to our check function
)
check_btn.pack(side="left", padx=12)

# "Clear" button — resets the form
clear_btn = tk.Button(
    buttons_frame,
    text="🗑️  Clear",
    font=button_font,
    bg="#0F3460",
    fg="#AAAACC",
    activebackground="#16213E",
    activeforeground="#FFFFFF",
    relief="flat",
    padx=22,
    pady=10,
    cursor="hand2",
    command=on_clear   # Link to our clear function
)
clear_btn.pack(side="left", padx=12)

# --- RESULT SECTION ---

# Thin divider before results
tk.Frame(root, bg="#0F3460", height=2, width=680).pack(pady=(4, 14))

# Main result label — shows "Password Strength: Strong / Medium / Weak"
result_label = tk.Label(
    root,
    text="",
    font=result_font,
    bg="#1A1A2E",
    fg="#FFFFFF"
)
result_label.pack(pady=(0, 4))

# Score label — shows "Security Score: 5 / 5 points"
score_label = tk.Label(
    root,
    text="",
    font=label_font,
    bg="#1A1A2E",
    fg="#FFFFFF"
)
score_label.pack(pady=(0, 8))

# Checks summary — shows which rules passed or failed
strength_label = tk.Label(
    root,
    text="",
    font=checks_font,
    bg="#1A1A2E",
    fg="#AAAAAA",
    wraplength=680
)
strength_label.pack(pady=(0, 8))

# Warning label — only visible when a common password is detected
warning_label = tk.Label(
    root,
    text="",
    font=label_font,
    bg="#1A1A2E",
    fg="#FF4C4C",
    wraplength=680
)
warning_label.pack(pady=(0, 10))

# Suggestions label — shows improvement tips
suggestions_label = tk.Label(
    root,
    text="",
    font=small_font,
    bg="#1A1A2E",
    fg="#CCCCCC",
    justify="left",       # Left-align multi-line text
    wraplength=680
)
suggestions_label.pack(pady=(0, 10))

# --- BOTTOM FOOTER ---
# A simple footer for branding
footer_bar = tk.Frame(root, bg="#0F3460", height=3)
footer_bar.pack(side="bottom", fill="x")

footer_label = tk.Label(
    root,
    text="🔐  Cyber Security Password Checker  |  Beginner Python Project",
    font=small_font,
    bg="#1A1A2E",
    fg="#444466"
)
footer_label.pack(side="bottom", pady=6)

# --- KEYBOARD SHORTCUT: Press ENTER to check the password ---
# Bind the <Return> key (Enter key) to the check function — improves usability
root.bind("<Return>", lambda event: on_check_password())


# ============================================================
# SECTION 7: START THE GUI EVENT LOOP
# ============================================================
# root.mainloop() keeps the window open and listening for user events
# (mouse clicks, keyboard input, button presses, etc.)
# Without this line, the window would flash open and immediately close.
root.mainloop()
