import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from prover import ProverScreen
from verifier import VerifierScreen



class DiscordStyleApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("NIZKP Forensics")
        self.root.geometry("1200x800")
        self.root.configure(bg='#36393f')

        # Color scheme
        self.colors = {
            'bg_color_primary': '#36393f',  # Main background
            'bg_color_secondary': '#2f3136',  # Sidebar
            'bg_color_tertiary': '#40444b',  # Cards/panels
            'accent': '#5865f2',  # Discord blue
            'accent_hover': '#4752c4',  # Darker blue
            'success': '#3ba55d',  # Green
            'danger': '#ed4245',  # Red
            'warning': '#faa61a',  # Orange
            'text_primary': '#ffffff',  # White text
            'text_secondary': '#b9bbbe',  # Gray text
            'text_muted': '#72767d',  # Muted text
        }

        self.current_screen = "home"
        self.selected_artifact = None
        self.create_ui()

    def create_ui(self):
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['bg_color_primary'])
        main_container.pack(fill=tk.BOTH, expand=True)

        # Sidebar
        self.create_sidebar(main_container)

        # Content area
        self.content_area = tk.Frame(main_container, bg=self.colors['bg_color_primary'])
        self.content_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Main content
        self.main_content = tk.Frame(self.content_area, bg=self.colors['bg_color_primary'])
        self.main_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Show home by default
        self.show_home()

    def create_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=self.colors['bg_color_secondary'], width=240)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        # Logo/Title
        title_frame = tk.Frame(sidebar, bg=self.colors['bg_color_secondary'])
        title_frame.pack(fill=tk.X, padx=16, pady=(16, 0))

        tk.Label(title_frame, text="NIZKP Forensics",
                 bg=self.colors['bg_color_secondary'], fg=self.colors['text_primary'],
                 font=('Segoe UI', 16, 'bold')).pack(anchor='w')

        # Navigation buttons
        nav_frame = tk.Frame(sidebar, bg=self.colors['bg_color_secondary'])
        nav_frame.pack(fill=tk.X, padx=8, pady=16)

        self.nav_buttons = {}
        nav_items = [
            ("🏠", "Home", "home"),
            ("📁", "Prover", "prover"),
            ("🔍", "Verifier", "verifier")
        ]

        for icon, text, screen in nav_items:
            button = self.create_nav_button(nav_frame, icon, text, screen)
            button.pack(fill=tk.X, pady=2)
            self.nav_buttons[screen] = button

        self.toggle_sidebar_button("prover", enabled=False)
        self.toggle_sidebar_button("verifier", enabled=False)

    def create_nav_button(self, parent, icon, text, screen):
        button_frame = tk.Frame(parent, bg=self.colors['bg_color_secondary'], cursor='hand2')

        # Button content
        button_content = tk.Frame(button_frame, bg=self.colors['bg_color_secondary'])
        button_content.pack(fill=tk.X, padx=8, pady=6)

        tk.Label(button_content, text=icon, bg=self.colors['bg_color_secondary'],
                 fg=self.colors['text_secondary'], font=('Segoe UI', 14)).pack(side=tk.LEFT)

        tk.Label(button_content, text=text, bg=self.colors['bg_color_secondary'],
                 fg=self.colors['text_secondary'], font=('Segoe UI', 11)).pack(side=tk.LEFT, padx=(8, 0))

        # Hover effects
        def on_enter(e):
            if self.current_screen != screen:
                button_frame.configure(bg=self.colors['bg_color_tertiary'])
                button_content.configure(bg=self.colors['bg_color_tertiary'])
                for child in button_content.winfo_children():
                    child.configure(bg=self.colors['bg_color_tertiary'])

        def on_leave(e):
            if self.current_screen != screen:
                button_frame.configure(bg=self.colors['bg_color_secondary'])
                button_content.configure(bg=self.colors['bg_color_secondary'])
                for child in button_content.winfo_children():
                    child.configure(bg=self.colors['bg_color_secondary'])

        def on_click(e):
            self.switch_screen(screen)

        button_frame.bind('<Enter>', on_enter)
        button_frame.bind('<Leave>', on_leave)
        button_frame.bind('<Button-1>', on_click)
        button_content.bind('<Button-1>', on_click)
        for child in button_content.winfo_children():
            child.bind('<Enter>', on_enter)
            child.bind('<Leave>', on_leave)
            child.bind('<Button-1>', on_click)

        return button_frame

    def create_top_bar(self):
        top_bar = tk.Frame(self.content_area, bg=self.colors['bg_color_primary'], height=60)
        top_bar.pack(fill=tk.X)
        top_bar.pack_propagate(False)

        # Add artifact type indicator if one is selected
        if self.selected_artifact:
            artifact_label = tk.Label(top_bar, text=f"Selected Artifact: {self.selected_artifact}",
                                      bg=self.colors['bg_color_primary'], fg=self.colors['text_secondary'],
                                      font=('Segoe UI', 12))
            artifact_label.pack(side=tk.RIGHT, padx=20, pady=15)

    def create_card(self, parent, title="", description=""):
        card = tk.Frame(parent, bg=self.colors['bg_color_tertiary'])

        if title:
            header = tk.Frame(card, bg=self.colors['bg_color_tertiary'])
            header.pack(fill=tk.X, padx=20, pady=(20, 10))

            tk.Label(header, text=title, bg=self.colors['bg_color_tertiary'],
                     fg=self.colors['text_primary'], font=('Segoe UI', 16, 'bold')).pack(anchor='w')

            if description:
                tk.Label(header, text=description, bg=self.colors['bg_color_tertiary'],
                         fg=self.colors['text_secondary'], font=('Segoe UI', 10)).pack(anchor='w', pady=(2, 0))

        content = tk.Frame(card, bg=self.colors['bg_color_tertiary'])
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

        return card, content

    def create_button(self, parent, text, command=None, style="primary"):
        colors = {
            'primary': (self.colors['accent'], self.colors['accent_hover']),
            'success': (self.colors['success'], '#2d7d32'),
            'danger': (self.colors['danger'], '#c62828'),
            'disabled': ('#4a4a4a', '#4a4a4a')
        }

        bg_color, hover_color = colors.get(style, colors['primary'])

        button = tk.Frame(parent, bg=bg_color, cursor='hand2' if style != 'disabled' else 'arrow')

        text_color = '#666666' if style == 'disabled' else 'white'
        label = tk.Label(button, text=text, bg=bg_color, fg=text_color,
                         font=('Segoe UI', 10, 'bold'), pady=10, padx=20)
        label.pack()

        # Store original command for later enabling
        button.original_command = command
        button.style = style

        if style != 'disabled':
            def on_enter(e):
                button.configure(bg=hover_color)
                label.configure(bg=hover_color)

            def on_leave(e):
                button.configure(bg=bg_color)
                label.configure(bg=bg_color)

            def on_click(e):
                if command and button.style != 'disabled':
                    command()

            button.bind('<Enter>', on_enter)
            button.bind('<Leave>', on_leave)
            button.bind('<Button-1>', on_click)
            label.bind('<Enter>', on_enter)
            label.bind('<Leave>', on_leave)
            label.bind('<Button-1>', on_click)

        return button

    def toggle_sidebar_button(self, screen, enabled=True):
        button = self.nav_buttons.get(screen)
        if not button:
            return

        bg_color = self.colors['bg_color_secondary'] if enabled else '#1e1f22'
        text_color = self.colors['text_secondary'] if enabled else self.colors['text_muted']
        cursor = 'hand2' if enabled else 'arrow'

        button.configure(bg=bg_color, cursor=cursor)
        for child in button.winfo_children():
            child.configure(bg=bg_color)
            for grandchild in child.winfo_children():
                grandchild.configure(bg=bg_color, fg=text_color)

        if enabled:
            def on_click(e):
                self.switch_screen(screen)
        else:
            def on_click(e):
                return

        # Rebind click events
        button.bind('<Button-1>', on_click)
        for child in button.winfo_children():
            child.bind('<Button-1>', on_click)
            for grandchild in child.winfo_children():
                grandchild.bind('<Button-1>', on_click)

    def show_home(self):
        # Reset the app to the home screen and disable Prover/Verifier
        self.selected_artifact = None  # Reset artifact selection
        self.toggle_sidebar_button("prover", enabled=False)
        self.toggle_sidebar_button("verifier", enabled=False)
        self.clear_content()

        # Center the artifact selection
        center_frame = tk.Frame(self.main_content, bg=self.colors['bg_color_primary'])
        center_frame.place(relx=0.5, rely=0.5, anchor='center')

        # Title
        tk.Label(center_frame, text="Select Artifact Type",
                 bg=self.colors['bg_color_primary'], fg=self.colors['text_primary'],
                 font=('Segoe UI', 24, 'bold')).pack(pady=(0, 40))

        # Artifact type cards
        artifacts_frame = tk.Frame(center_frame, bg=self.colors['bg_color_primary'])
        artifacts_frame.pack()

        artifacts = [
            ("📦", "PCAP", "Network Traffic Capture"),
            ("💾", "Memory Dump", "Windows Memory Analysis"),
            ("💿", "Disk Image", "Hard Drive Analysis"),
            ("📋", "Registry", "Windows Registry Analysis")
        ]

        self.artifact_cards = {}

        for i, (icon, title, desc) in enumerate(artifacts):
            card = tk.Frame(artifacts_frame, bg=self.colors['bg_color_tertiary'], cursor='hand2')
            card.grid(row=0, column=i, padx=15, pady=15)

            # Card content
            content = tk.Frame(card, bg=self.colors['bg_color_tertiary'])
            content.pack(padx=30, pady=30)

            icon_label = tk.Label(content, text=icon, bg=self.colors['bg_color_tertiary'],
                                  fg=self.colors['text_primary'], font=('Segoe UI', 32))
            icon_label.pack(pady=(0, 10))

            title_label = tk.Label(content, text=title, bg=self.colors['bg_color_tertiary'],
                                   fg=self.colors['text_primary'], font=('Segoe UI', 14, 'bold'))
            title_label.pack()

            desc_label = tk.Label(content, text=desc, bg=self.colors['bg_color_tertiary'],
                                  fg=self.colors['text_secondary'], font=('Segoe UI', 10))
            desc_label.pack(pady=(5, 0))

            # Store card and its components for highlighting
            self.artifact_cards[title] = {
                'card': card,
                'content': content,
                'children': [icon_label, title_label, desc_label]
            }

            # Hover and click effects
            def make_click_handler(artifact_type):
                def on_click(e):
                    self.select_artifact(artifact_type)

                return on_click

            def make_hover_effect(artifact_type):
                def on_enter(e):
                    if self.selected_artifact != artifact_type:
                        self.highlight_card(artifact_type, self.colors['accent'])

                def on_leave(e):
                    if self.selected_artifact != artifact_type:
                        self.highlight_card(artifact_type, self.colors['bg_color_tertiary'])

                return on_enter, on_leave

            enter, leave = make_hover_effect(title)
            click = make_click_handler(title)

            # Bind events to all components
            for component in [card, content] + [icon_label, title_label, desc_label]:
                component.bind('<Enter>', enter)
                component.bind('<Leave>', leave)
                component.bind('<Button-1>', click)

    def show_prover(self):
        self.clear_content()

        # Create a custom frame that matches Discord styling
        prover_wrapper = tk.Frame(self.main_content, bg=self.colors['bg_color_primary'])
        prover_wrapper.pack(fill="both", expand=True)

        # Add title bar for prover
        title_frame = tk.Frame(prover_wrapper, bg=self.colors['bg_color_primary'])
        title_frame.pack(fill="x", pady=(0, 10))

        tk.Label(title_frame, text=f"📦 {self.selected_artifact} Prover",
                 bg=self.colors['bg_color_primary'], fg=self.colors['text_primary'],
                 font=('Segoe UI', 18, 'bold')).pack(side="left")

        # Create the prover interface with Discord-style background
        prover_ui = ProverScreen(prover_wrapper)
        print("DEBUG: ProverScreen.display_summary = ", hasattr(prover_ui, "display_summary"))
        prover_ui.configure(bg=self.colors['bg_color_primary'])
        prover_ui.pack(fill="both", expand=True)

    def show_verifier(self):
        self.clear_content()

        # Title
        title_frame = tk.Frame(self.main_content, bg=self.colors['bg_color_primary'])
        title_frame.pack(fill="x", pady=(0, 20))

        tk.Label(title_frame, text="🔍 PCAP Verifier",
                 bg=self.colors['bg_color_primary'], fg=self.colors['text_primary'],
                 font=('Segoe UI', 18, 'bold')).pack(side="left")

        # Import proof
        import_card, import_content = self.create_card(self.main_content,
                                                       "Import Proof",
                                                       "Load a zero-knowledge proof for verification")
        import_card.pack(fill=tk.X, pady=(0, 20))

        import_button = self.create_button(import_content, "📄 Import Proof File", self.import_proof)
        import_button.pack(anchor='w')

        self.proof_status = tk.Label(import_content, text="No proof loaded",
                                     bg=self.colors['bg_color_tertiary'], fg=self.colors['text_muted'])
        self.proof_status.pack(anchor='w', pady=(10, 0))

        # Results area
        self.results_card, self.results_content = self.create_card(self.main_content, "Verification Results")
        self.results_card.pack(fill=tk.BOTH, expand=True)

        placeholder = tk.Label(self.results_content, text="Import a proof file to see verification results",
                               bg=self.colors['bg_color_tertiary'], fg=self.colors['text_muted'],
                               font=('Segoe UI', 12))
        placeholder.pack(expand=True)

    def show_settings(self):
        self.clear_content()
        settings_card, settings_content = self.create_card(self.main_content, "Settings")
        settings_card.pack(fill=tk.X)
        tk.Label(settings_content, text="Configuration options coming soon...",
                 bg=self.colors["bg_color_tertiary"], fg=self.colors["text_muted"]).pack(pady=20)

    def switch_screen(self, screen):
        # Check if trying to access prover/verifier without artifact selection
        if screen in ["prover", "verifier"] and not self.selected_artifact:
            messagebox.showwarning("No Artifact Selected",
                                   "Please select an artifact type first.")
            return

        # Update nav button states
        for nav_screen, button in self.nav_buttons.items():
            if nav_screen == screen:
                button.configure(bg=self.colors['accent'])
                for child in button.winfo_children():
                    child.configure(bg=self.colors['accent'])
                    for grandchild in child.winfo_children():
                        grandchild.configure(bg=self.colors['accent'], fg='white')
            else:
                button.configure(bg=self.colors['bg_color_secondary'])
                for child in button.winfo_children():
                    child.configure(bg=self.colors['bg_color_secondary'])
                    for grandchild in child.winfo_children():
                        grandchild.configure(bg=self.colors['bg_color_secondary'],
                                             fg=self.colors['text_secondary'])

        self.current_screen = screen

        # Show appropriate content
        if screen == "home":
            self.show_home()
        elif screen == "prover":
            self.show_prover()
        elif screen == "verifier":
            self.show_verifier()

    def clear_content(self):
        for widget in self.main_content.winfo_children():
            widget.destroy()

    def highlight_card(self, artifact_type, color):
        """Highlight or unhighlight an artifact card"""
        if artifact_type in self.artifact_cards:
            card_data = self.artifact_cards[artifact_type]
            card_data['card'].configure(bg=color)
            card_data['content'].configure(bg=color)
            for child in card_data['children']:
                child.configure(bg=color)

    def select_artifact(self, artifact):
        # Unhighlight previous selection
        if self.selected_artifact:
            self.highlight_card(self.selected_artifact, self.colors['bg_color_tertiary'])

        # Highlight new selection and enable navigation
        self.selected_artifact = artifact
        self.highlight_card(artifact, self.colors['success'])
        self.toggle_sidebar_button("prover", enabled=True)
        self.toggle_sidebar_button("verifier", enabled=True)

    def import_proof(self):
        file_path = filedialog.askopenfilename(
            title="Import Proof",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                import json
                with open(file_path, 'r') as f:
                    self.proof_data = json.load(f)  # Store proof data

                filename = file_path.split('/')[-1]
                self.proof_status.config(text=f"✅ {filename}", fg=self.colors['success'])

                # Clear previous results and show input form
                self.show_verification_input_form()

            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import proof:\n{str(e)}")

    def show_verification_results(self, proof_data):
        for widget in self.results_content.winfo_children():
            widget.destroy()

        # Success message
        tk.Label(self.results_content, text="✅ PROOF VERIFIED",
                 bg=self.colors['bg_color_tertiary'], fg=self.colors['success'],
                 font=('Segoe UI', 16, 'bold')).pack(pady=(20, 10))

        # Proof details
        details_frame = tk.Frame(self.results_content, bg=self.colors['bg_color_tertiary'])
        details_frame.pack(fill="x", pady=10)

        # Display proof information
        info_items = [
            ("Tool", proof_data.get("tool", "Unknown")),
            ("Version", proof_data.get("version", "Unknown")),
            ("Generated", proof_data.get("generated", "Unknown")),
            ("File Analyzed", proof_data.get("file_analyzed", "Unknown"))
        ]

        for i, (label, value) in enumerate(info_items):
            row_frame = tk.Frame(details_frame, bg=self.colors['bg_color_tertiary'])
            row_frame.pack(fill="x", pady=2)

            tk.Label(row_frame, text=f"{label}:",
                     bg=self.colors['bg_color_tertiary'], fg=self.colors['text_secondary'],
                     font=('Segoe UI', 10, 'bold'), width=15, anchor="e").pack(side="left")

            tk.Label(row_frame, text=value,
                     bg=self.colors['bg_color_tertiary'], fg=self.colors['text_primary'],
                     font=('Segoe UI', 10)).pack(side="left", padx=(10, 0))

        # Verification checks
        tk.Label(self.results_content, text="Verification Checks:",
                 bg=self.colors['bg_color_tertiary'], fg=self.colors['text_primary'],
                 font=('Segoe UI', 12, 'bold')).pack(anchor="w", pady=(20, 5))

        checks = [
            "Cryptographic signature valid",
            "Zero-knowledge proof verified",
            "Data integrity confirmed",
            "Proof structure validated"
        ]

        for check in checks:
            tk.Label(self.results_content, text=check,
                     bg=self.colors['bg_color_tertiary'], fg=self.colors['success'],
                     font=('Segoe UI', 10)).pack(anchor='w', pady=2)

    def show_verification_input_form(self):
        """Show form for verifier to enter password and connection details (improved)"""
        for widget in self.results_content.winfo_children():
            widget.destroy()

        # Password input group
        password_frame = tk.LabelFrame(self.results_content, text="🔐 Proof Password",
                                       bg=self.colors['bg_color_tertiary'], fg=self.colors['text_primary'],
                                       font=('Segoe UI', 12, 'bold'), padx=10, pady=10)
        password_frame.pack(fill="x", pady=(20, 10))

        self.verify_password_entry = tk.Entry(password_frame, show="*", width=30, font=('Segoe UI', 10))
        self.verify_password_entry.pack(anchor="w", pady=(5, 0))

        # Connection details group
        connection_frame = tk.LabelFrame(self.results_content, text="🔍 Connection to Verify",
                                         bg=self.colors['bg_color_tertiary'], fg=self.colors['text_primary'],
                                         font=('Segoe UI', 12, 'bold'), padx=10, pady=10)
        connection_frame.pack(fill="x", pady=10)

        # Input grid
        input_grid = tk.Frame(connection_frame, bg=self.colors['bg_color_tertiary'])
        input_grid.pack(fill="x", pady=(10, 0))

        # Source IP
        tk.Label(input_grid, text="Source IP:", bg=self.colors['bg_color_tertiary'],
                 fg=self.colors['text_secondary']).grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.verify_src_ip = tk.Entry(input_grid, width=15)
        self.verify_src_ip.grid(row=0, column=1, padx=(0, 20))

        # Source Port
        tk.Label(input_grid, text="Source Port:", bg=self.colors['bg_color_tertiary'],
                 fg=self.colors['text_secondary']).grid(row=0, column=2, sticky="w", padx=(0, 10))
        self.verify_src_port = tk.Entry(input_grid, width=8)
        self.verify_src_port.grid(row=0, column=3, padx=(0, 20))

        # Destination IP
        tk.Label(input_grid, text="Destination IP:", bg=self.colors['bg_color_tertiary'],
                 fg=self.colors['text_secondary']).grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(10, 0))
        self.verify_dst_ip = tk.Entry(input_grid, width=15)
        self.verify_dst_ip.grid(row=1, column=1, padx=(0, 20), pady=(10, 0))

        # Destination Port
        tk.Label(input_grid, text="Destination Port:", bg=self.colors['bg_color_tertiary'],
                 fg=self.colors['text_secondary']).grid(row=1, column=2, sticky="w", padx=(0, 10), pady=(10, 0))
        self.verify_dst_port = tk.Entry(input_grid, width=8)
        self.verify_dst_port.grid(row=1, column=3, padx=(0, 20), pady=(10, 0))

        # Protocol
        tk.Label(input_grid, text="Protocol:", bg=self.colors['bg_color_tertiary'],
                 fg=self.colors['text_secondary']).grid(row=2, column=0, sticky="w", padx=(0, 10), pady=(10, 0))
        self.verify_protocol = tk.Entry(input_grid, width=15)
        self.verify_protocol.grid(row=2, column=1, padx=(0, 20), pady=(10, 0))

        # Format hint
        hint_label = tk.Label(connection_frame,
                              text="Format: SourceIP:SrcPort → DestIP:DstPort (Protocol)\nExample: 192.168.1.5:443 → 8.8.8.8:443 (TCP)",
                              bg=self.colors['bg_color_tertiary'], fg=self.colors['text_secondary'],
                              font=('Segoe UI', 9, 'italic'))
        hint_label.pack(anchor="w", pady=(10, 5))

        # Verify button
        verify_button = self.create_button(self.results_content, "🔍 Verify Proof", self.perform_verification)
        verify_button.pack(pady=20)

    def import_proof(self):
        file_path = filedialog.askopenfilename(
            title="Import Proof",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                import json
                with open(file_path, 'r') as f:
                    self.proof_data = json.load(f)  # Store proof data

                filename = file_path.split('/')[-1]
                self.proof_status.config(text=f"✅ {filename}", fg=self.colors['success'])

                # Clear previous results and show input form
                self.show_verification_input_form()

            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import proof:\n{str(e)}")

    def show_verification_input_form(self):
        """Show form for verifier to enter password and connection details (improved)"""
        for widget in self.results_content.winfo_children():
            widget.destroy()

        # Password input group
        password_frame = tk.LabelFrame(self.results_content, text="🔐 Proof Password",
                                       bg=self.colors['bg_color_tertiary'], fg=self.colors['text_primary'],
                                       font=('Segoe UI', 12, 'bold'), padx=10, pady=10)
        password_frame.pack(fill="x", pady=(20, 10))

        self.verify_password_entry = tk.Entry(password_frame, show="*", width=30, font=('Segoe UI', 10))
        self.verify_password_entry.pack(anchor="w", pady=(5, 0))

        # Connection details group
        connection_frame = tk.LabelFrame(self.results_content, text="🔍 Connection to Verify",
                                         bg=self.colors['bg_color_tertiary'], fg=self.colors['text_primary'],
                                         font=('Segoe UI', 12, 'bold'), padx=10, pady=10)
        connection_frame.pack(fill="x", pady=10)

        # Input grid
        input_grid = tk.Frame(connection_frame, bg=self.colors['bg_color_tertiary'])
        input_grid.pack(fill="x", pady=(10, 0))

        # Source IP
        tk.Label(input_grid, text="Source IP:", bg=self.colors['bg_color_tertiary'],
                 fg=self.colors['text_secondary']).grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.verify_src_ip = tk.Entry(input_grid, width=15)
        self.verify_src_ip.grid(row=0, column=1, padx=(0, 20))

        # Source Port
        tk.Label(input_grid, text="Source Port:", bg=self.colors['bg_color_tertiary'],
                 fg=self.colors['text_secondary']).grid(row=0, column=2, sticky="w", padx=(0, 10))
        self.verify_src_port = tk.Entry(input_grid, width=8)
        self.verify_src_port.grid(row=0, column=3, padx=(0, 20))

        # Destination IP
        tk.Label(input_grid, text="Destination IP:", bg=self.colors['bg_color_tertiary'],
                 fg=self.colors['text_secondary']).grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(10, 0))
        self.verify_dst_ip = tk.Entry(input_grid, width=15)
        self.verify_dst_ip.grid(row=1, column=1, padx=(0, 20), pady=(10, 0))

        # Destination Port
        tk.Label(input_grid, text="Destination Port:", bg=self.colors['bg_color_tertiary'],
                 fg=self.colors['text_secondary']).grid(row=1, column=2, sticky="w", padx=(0, 10), pady=(10, 0))
        self.verify_dst_port = tk.Entry(input_grid, width=8)
        self.verify_dst_port.grid(row=1, column=3, padx=(0, 20), pady=(10, 0))

        # Protocol
        tk.Label(input_grid, text="Protocol:", bg=self.colors['bg_color_tertiary'],
                 fg=self.colors['text_secondary']).grid(row=2, column=0, sticky="w", padx=(0, 10), pady=(10, 0))
        self.verify_protocol = tk.Entry(input_grid, width=15)
        self.verify_protocol.grid(row=2, column=1, padx=(0, 20), pady=(10, 0))

        # Payload/Keyword (OPTIONAL)
        tk.Label(input_grid, text="Payload (Optional):", bg=self.colors['bg_color_tertiary'],
                 fg=self.colors['text_secondary']).grid(row=2, column=2, sticky="w", padx=(0, 10), pady=(10, 0))
        self.verify_payload = tk.Entry(input_grid, width=25)
        self.verify_payload.grid(row=2, column=3, columnspan=2, padx=(0, 20), pady=(10, 0), sticky="w")

        # Format hint - UPDATED to include payload
        hint_label = tk.Label(connection_frame,
                              text="Format: SourceIP:SrcPort → DestIP:DstPort (Protocol) | Payload (optional)\n" +
                                   "Example: 192.168.1.5:443 → 8.8.8.8:443 (TCP) | GET /index.html\n" +
                                   "Note: Leave payload empty for basic connection verification",
                              bg=self.colors['bg_color_tertiary'], fg=self.colors['text_secondary'],
                              font=('Segoe UI', 9, 'italic'))
        hint_label.pack(anchor="w", pady=(10, 5))

        # Verify button
        verify_button = self.create_button(self.results_content, "🔍 Verify Proof", self.perform_verification)
        verify_button.pack(pady=20)

    def perform_verification(self):
        """Perform the actual verification with user input"""
        if not hasattr(self, 'proof_data'):
            messagebox.showerror("No Proof", "Please import a proof file first.")
            return

        password = self.verify_password_entry.get()
        if not password:
            messagebox.showerror("Missing Password", "Please enter the proof password.")
            return

        # Check if connection details are provided
        src_ip = self.verify_src_ip.get().strip()
        dst_ip = self.verify_dst_ip.get().strip()
        protocol = self.verify_protocol.get().strip()
        src_port = self.verify_src_port.get().strip()
        dst_port = self.verify_dst_port.get().strip()

        # Get payload if field exists (it might not exist in older UI versions)
        payload = ""
        if hasattr(self, 'verify_payload'):
            payload = self.verify_payload.get().strip()

        if not all([src_ip, dst_ip, protocol, src_port, dst_port]):
            messagebox.showerror("Missing Details",
                                 "Please fill in all required connection details (payload is optional).")
            return

        try:
            # Format basic connection string (without payload)
            connection_string = f"{src_ip}:{src_port}->{dst_ip}:{dst_port} ({protocol})"

            print(f"DEBUG: Verifying connection: {connection_string}")
            if payload:
                print(f"DEBUG: With payload: {payload}")
            else:
                print("DEBUG: No payload provided - basic verification only")

            # Import verification function
            from zk_engine import verify_privacy_preserving_proof

            # Perform verification with optional payload
            if payload:
                valid, message = verify_privacy_preserving_proof(self.proof_data, password, connection_string, payload)
            else:
                valid, message = verify_privacy_preserving_proof(self.proof_data, password, connection_string)

            if valid:
                self.show_verification_success(message)
            else:
                self.show_verification_failure(message)

        except Exception as e:
            messagebox.showerror("Verification Error", f"Failed to verify proof:\n{str(e)}")
            # Print full traceback for debugging
            import traceback
            print("VERIFICATION ERROR TRACEBACK:")
            traceback.print_exc()

    def show_verification_success(self, message):
        """Show successful verification results"""
        for widget in self.results_content.winfo_children():
            widget.destroy()

        # Success message
        tk.Label(self.results_content, text="✅ PROOF VERIFIED",
                 bg=self.colors['bg_color_tertiary'], fg=self.colors['success'],
                 font=('Segoe UI', 16, 'bold')).pack(pady=(20, 10))

        tk.Label(self.results_content, text=message,
                 bg=self.colors['bg_color_tertiary'], fg=self.colors['text_primary'],
                 font=('Segoe UI', 12)).pack(pady=10)

        # Verification checks - UPDATED based on message content
        checks = []
        if "payload verified" in message.lower():
            checks = [
                "✅ Password verification successful",
                "✅ Connection found in encrypted filter",
                "✅ Payload content verified",
                "✅ Cryptographic signature valid",
                "✅ Zero-knowledge proof verified"
            ]
        elif "payload doesn't match" in message.lower():
            checks = [
                "✅ Password verification successful",
                "✅ Connection found in encrypted filter",
                "⚠️ Payload content doesn't match",
                "✅ Cryptographic signature valid",
                "✅ Zero-knowledge proof verified"
            ]
        elif "payload not checked" in message.lower():
            checks = [
                "✅ Password verification successful",
                "✅ Connection found in encrypted filter",
                "ℹ️ Payload not provided (basic verification)",
                "✅ Cryptographic signature valid",
                "✅ Zero-knowledge proof verified"
            ]
        else:
            checks = [
                "✅ Password verification successful",
                "✅ Connection verified",
                "✅ Cryptographic signature valid",
                "✅ Zero-knowledge proof verified"
            ]

        for check in checks:
            color = self.colors['success']
            if check.startswith('⚠️'):
                color = self.colors['warning']
            elif check.startswith('ℹ️'):
                color = self.colors['text_secondary']

            tk.Label(self.results_content, text=check,
                     bg=self.colors['bg_color_tertiary'], fg=color,
                     font=('Segoe UI', 10)).pack(anchor='w', pady=2)

    def show_verification_failure(self, message):
        """Show failed verification results"""
        for widget in self.results_content.winfo_children():
            widget.destroy()

        # Failure message
        tk.Label(self.results_content, text="VERIFICATION FAILED",
                 bg=self.colors['bg_color_tertiary'], fg=self.colors['danger'],
                 font=('Segoe UI', 16, 'bold')).pack(pady=(20, 10))

        tk.Label(self.results_content, text=message,
                 bg=self.colors['bg_color_tertiary'], fg=self.colors['text_primary'],
                 font=('Segoe UI', 12)).pack(pady=10)

    def run(self):
        # Center the window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (1200 // 2)
        y = (self.root.winfo_screenheight() // 2) - (800 // 2)
        self.root.geometry(f"1200x800+{x}+{y}")

        self.root.mainloop()


if __name__ == "__main__":
    app = DiscordStyleApp()
    app.run()