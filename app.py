import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import sv_ttk  # ModernTkinter for Theming
import json
import os
from AudioStegnographyAlgo.LSBAudioStego import LSBAudioStego
from AudioStegnographyAlgo.PhaseEncodingAudioStego import PhaseEncodingAudioStego

class AudioSteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LSB Audio Steganography")
        self.root.geometry("447x465")
        self.root.resizable(False, False)  # Fixed size window
        sv_ttk.set_theme("dark")  # Set initial dark theme

        # Load registered users from file
        self.registered_users = self.load_users()

        # Theme toggle variable
        self.theme_var = tk.BooleanVar(value=True)  # True for dark, False for light

        # Create frames
        self.create_login_frame()
        self.create_signup_frame()
        self.create_main_menu_frame()
        self.create_encode_frame()
        self.create_decode_frame()

        # Show login frame initially
        self.show_login()

    def load_users(self):
        """Load registered users from a JSON file."""
        if os.path.exists("users.json"):
            with open("users.json", "r") as file:
                return json.load(file)
        return {}

    def save_users(self):
        """Save registered users to a JSON file."""
        with open("users.json", "w") as file:
            json.dump(self.registered_users, file)

    def create_login_frame(self):
        """Create the login frame."""
        self.login_frame = ttk.Frame(self.root)

        ttk.Label(self.login_frame, text="Login", font=("Arial", 16)).pack(pady=10)

        ttk.Label(self.login_frame, text="Username:").pack(anchor="w", padx=20)
        self.login_username = ttk.Entry(self.login_frame, width=30)
        self.login_username.pack(fill="x", padx=20, pady=5)

        ttk.Label(self.login_frame, text="Password:").pack(anchor="w", padx=20)
        self.login_password = ttk.Entry(self.login_frame, width=30, show="*")
        self.login_password.pack(fill="x", padx=20, pady=5)

        ttk.Button(self.login_frame, text="Login", command=self.login).pack(pady=10)
        ttk.Button(self.login_frame, text="Signup", command=self.show_signup).pack(pady=10)

        # Theme Toggle
        toggle_frame = ttk.Frame(self.login_frame)
        toggle_frame.place(relx=1.0, y=10, anchor="ne")
        ttk.Checkbutton(toggle_frame, variable=self.theme_var, onvalue=True, offvalue=False,
                         style="Switch.TCheckbutton", command=self.toggle_theme).pack(side="left")

    def create_signup_frame(self):
        """Create the signup frame."""
        self.signup_frame = ttk.Frame(self.root)

        ttk.Label(self.signup_frame, text="Signup", font=("Arial", 16)).pack(pady=10)

        ttk.Label(self.signup_frame, text="Username:").pack(anchor="w", padx=20)
        self.signup_username = ttk.Entry(self.signup_frame, width=30)
        self.signup_username.pack(fill="x", padx=20, pady=5)

        ttk.Label(self.signup_frame, text="Password:").pack(anchor="w", padx=20)
        self.signup_password = ttk.Entry(self.signup_frame, width=30, show="*")
        self.signup_password.pack(fill="x", padx=20, pady=5)

        ttk.Label(self.signup_frame, text="Confirm Password:").pack(anchor="w", padx=20)
        self.signup_confirm_password = ttk.Entry(self.signup_frame, width=30, show="*")
        self.signup_confirm_password.pack(fill="x", padx=20, pady=5)

        ttk.Button(self.signup_frame, text="Signup", command=self.signup).pack(pady=10)
        ttk.Button(self.signup_frame, text="Back", command=self.show_login).pack(side="right", padx=10, pady=20)

        # Theme Toggle
        toggle_frame = ttk.Frame(self.signup_frame)
        toggle_frame.place(relx=1.0, y=10, anchor="ne")
        ttk.Checkbutton(toggle_frame, variable=self.theme_var, onvalue=True, offvalue=False,
                         style="Switch.TCheckbutton", command=self.toggle_theme).pack(side="left")

    def create_main_menu_frame(self):
        """Create the main menu frame."""
        self.main_menu_frame = ttk.Frame(self.root)

        ttk.Label(self.main_menu_frame, text="LSB Audio Steganography", font=("Arial", 16)).pack(pady=5)
        ttk.Button(self.main_menu_frame, text="Encode Audio", command=self.show_encode).pack(pady=5)
        ttk.Button(self.main_menu_frame, text="Decode Audio", command=self.show_decode).pack(pady=5)
        ttk.Button(self.main_menu_frame, text="Exit", command=self.root.quit).pack(pady=10)

        

    def create_encode_frame(self):
        """Create the encode frame."""
        self.encode_frame = ttk.Frame(self.root)

        ttk.Label(self.encode_frame, text="Audio Encoding", font=("Arial", 16)).pack(pady=10)
        
        self.selected_file = tk.StringVar()
        ttk.Label(self.encode_frame, textvariable=self.selected_file).pack(pady=5)
        ttk.Button(self.encode_frame, text="Select Audio File", command=self.select_file).pack(pady=5)
        
        ttk.Label(self.encode_frame, text="Enter Message to Encode:").pack()
        self.message_entry = ttk.Entry(self.encode_frame, width=30)
        self.message_entry.pack(pady=5)
        
        self.encoding_algorithm = tk.StringVar(value="Least Significant Bit")
        ttk.Label(self.encode_frame, text="Select Encoding Algorithm:").pack()
        ttk.Combobox(self.encode_frame, textvariable=self.encoding_algorithm, values=["Least Significant Bit", "Phase Coding"]).pack(pady=5)
        
        ttk.Button(self.encode_frame, text="Encode", command=self.encode_audio).pack(pady=10)
        ttk.Button(self.encode_frame, text="Back", command=self.show_main_menu).pack(side="right", padx=10, pady=10)

    def create_decode_frame(self):
        """Create the decode frame."""
        self.decode_frame = ttk.Frame(self.root)

        ttk.Label(self.decode_frame, text="Audio Decoding", font=("Arial", 16)).pack(pady=10)
        
        self.selected_decode_file = tk.StringVar()
        ttk.Label(self.decode_frame, textvariable=self.selected_decode_file).pack(pady=5)
        ttk.Button(self.decode_frame, text="Select Encoded Audio File", command=self.select_decode_file).pack(pady=5)
        
        self.decoding_algorithm = tk.StringVar(value="Least Significant Bit")
        ttk.Label(self.decode_frame, text="Select Decoding Algorithm:").pack()
        ttk.Combobox(self.decode_frame, textvariable=self.decoding_algorithm, values=["Least Significant Bit", "Phase Coding"]).pack(pady=5)
        
        self.decoded_message = tk.StringVar()
        ttk.Label(self.decode_frame, textvariable=self.decoded_message, font=("Arial", 14)).pack(pady=10)
        
        ttk.Button(self.decode_frame, text="Decode", command=self.decode_audio).pack(pady=10)
        ttk.Button(self.decode_frame, text="Back", command=self.show_main_menu).pack(side="right", padx=10, pady=10)

    def show_login(self):
        """Show the login frame."""
        self.signup_frame.pack_forget()
        self.main_menu_frame.pack_forget()
        self.encode_frame.pack_forget()
        self.decode_frame.pack_forget()
        self.login_frame.pack(pady=50)

    def show_signup(self):
        """Show the signup frame."""
        self.login_frame.pack_forget()
        self.main_menu_frame.pack_forget()
        self.encode_frame.pack_forget()
        self.decode_frame.pack_forget()
        self.signup_frame.pack(pady=50)

    def show_main_menu(self):
        """Show the main menu frame."""
        self.login_frame.pack_forget()
        self.signup_frame.pack_forget()
        self.encode_frame.pack_forget()
        self.decode_frame.pack_forget()
        self.main_menu_frame.pack(pady=50)

    def show_encode(self):
        """Show the encode frame."""
        self.main_menu_frame.pack_forget()
        self.decode_frame.pack_forget()
        self.encode_frame.pack(pady=50)

    def show_decode(self):
        """Show the decode frame."""
        self.main_menu_frame.pack_forget()
        self.encode_frame.pack_forget()
        self.decode_frame.pack(pady=50)

    def login(self):
        """Handle user login."""
        username = self.login_username.get().strip()
        password = self.login_password.get().strip()

        if username in self.registered_users and self.registered_users[username] == password:
            messagebox.showinfo("Login Successful", "Welcome!")
            self.show_main_menu()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials!")

    def signup(self):
        """Handle user signup."""
        username = self.signup_username.get().strip()
        password = self.signup_password.get().strip()
        confirm_password = self.signup_confirm_password.get().strip()

        if not username or not password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields!")
        elif password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
        elif username in self.registered_users:
            messagebox.showerror("Error", "Username already exists!")
        else:
            self.registered_users[username] = password
            self.save_users()
            messagebox.showinfo("Success", "Account created successfully!")
            self.show_login()

    def toggle_theme(self):
        """Toggle between dark and light themes."""
        if self.theme_var.get():
            sv_ttk.set_theme("dark")
        else:
            sv_ttk.set_theme("light")

    def select_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("WAV Files", "*.wav")])
        if file_path:
            self.selected_file.set(file_path)
    
    def select_decode_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("WAV Files", "*.wav")])
        if file_path:
            self.selected_decode_file.set(file_path)
    
    def encode_audio(self):
        if not self.selected_file.get() or not self.message_entry.get():
            messagebox.showerror("Error", "Please select a file and enter a message.")
            return
        
        algo = LSBAudioStego() if self.encoding_algorithm.get() == "Least Significant Bit" else PhaseEncodingAudioStego()
        result = algo.encodeAudio(self.selected_file.get(), self.message_entry.get())
        messagebox.showinfo("Success", f"Encoded file saved at: {result}")
    
    def decode_audio(self):
        if not self.selected_decode_file.get():
            messagebox.showerror("Error", "Please select a file.")
            return
        
        algo = LSBAudioStego() if self.decoding_algorithm.get() == "Least Significant Bit" else PhaseEncodingAudioStego()
        result = algo.decodeAudio(self.selected_decode_file.get())
        self.decoded_message.set(f"Decoded Message: {result}")
        messagebox.showinfo("Decoded Message", result)

if __name__ == "__main__":
    root = tk.Tk()
    app = AudioSteganographyApp(root)
    root.mainloop()