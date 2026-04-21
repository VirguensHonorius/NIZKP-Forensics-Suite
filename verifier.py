
import tkinter as tk
from tkinter import filedialog, messagebox
import os
from zk_engine import verify_privacy_preserving_proof

class VerifierScreen(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        self.canvas = tk.Canvas(self)
        self.scrollbar = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.proof_path = None
        self.password = tk.StringVar()
        self.src_ip = tk.StringVar()
        self.dst_ip = tk.StringVar()
        self.protocol = tk.StringVar()
        self.src_port = tk.StringVar()
        self.dst_port = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.scrollable_frame, text="Verifier Module", font=("Helvetica", 16)).pack(pady=10)

        tk.Button(self.scrollable_frame, text="Select Proof File", command=self.select_proof_file).pack(pady=10)

        tk.Label(self.scrollable_frame, text="Proof Password:").pack(pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.password, show="*").pack(pady=5)

        # Connection fields
        tk.Label(self.scrollable_frame, text="Source IP:").pack(pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.src_ip).pack(pady=5)

        tk.Label(self.scrollable_frame, text="Destination IP:").pack(pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.dst_ip).pack(pady=5)

        tk.Label(self.scrollable_frame, text="Protocol:").pack(pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.protocol).pack(pady=5)

        tk.Label(self.scrollable_frame, text="Source Port:").pack(pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.src_port).pack(pady=5)

        tk.Label(self.scrollable_frame, text="Destination Port:").pack(pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.dst_port).pack(pady=5)

        tk.Button(self.scrollable_frame, text="Verify Proof", command=self.verify_proof).pack(pady=20)

    def select_proof_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")])
        if file_path:
            self.proof_path = file_path
            messagebox.showinfo("File Selected", f"Selected: {os.path.basename(file_path)}")

    def verify_proof(self):
        if not self.proof_path:
            messagebox.showerror("Error", "Please select a proof file.")
            return

        if not self.password.get():
            messagebox.showerror("Error", "Please enter a proof password.")
            return

        try:
            # Load the proof file
            import json
            with open(self.proof_path, 'r') as f:
                proof_data = json.load(f)

            # ADD THIS EXPIRATION CHECK:
            if 'expires_at' in proof_data:
                from datetime import datetime, timezone
                expires_at = datetime.fromisoformat(proof_data['expires_at'].replace('Z', '+00:00'))
                if datetime.now(timezone.utc) > expires_at:
                    messagebox.showerror("Expired Proof",
                                         f"This proof expired on {expires_at.strftime('%Y-%m-%d %H:%M UTC')}")
                    return
                else:
                    # Show expiration info
                    days_left = (expires_at - datetime.now(timezone.utc)).days
                    messagebox.showinfo("Proof Status",
                                        f"Proof expires in {days_left} days\n({expires_at.strftime('%Y-%m-%d %H:%M UTC')})")

            # Continue with existing verification code...
            connection_to_verify = {
                'src_ip': self.src_ip.get(),
                'dst_ip': self.dst_ip.get(),
                'protocol': self.protocol.get(),
                'src_port': self.src_port.get(),
                'dst_port': self.dst_port.get()
            }

            # Convert connection to string format expected by verify function
            connection_string = f"{connection_to_verify['src_ip']}:{connection_to_verify['src_port']}->{connection_to_verify['dst_ip']}:{connection_to_verify['dst_port']} ({connection_to_verify['protocol']})"

            valid, message = verify_privacy_preserving_proof(proof_data, self.password.get(), connection_string)
            if valid:
                messagebox.showinfo("Success", f"Proof verified successfully!\n{message}")
            else:
                messagebox.showerror("Invalid Proof", f"Proof verification failed!\n{message}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to verify proof: {str(e)}")