def apply_theme(root):
    """Apply a consistent theme to the application"""
    style = {
        'TFrame': {
            'background': '#ffffff'
        },
        'TLabel': {
            'background': '#ffffff',
            'foreground': '#333333',
            'font': ('Arial', 10)
        },
        'TButton': {
            'background': '#003366',
            'foreground': 'white',
            'font': ('Arial', 10, 'bold'),
            'borderwidth': 1,
            'relief': 'raised',
            'padding': (10, 5)
        },
        'TEntry': {
            'fieldbackground': '#ffffff',
            'foreground': '#333333',
            'font': ('Arial', 10),
            'padding': (5, 5)
        },
        'TCombobox': {
            'fieldbackground': '#ffffff',
            'foreground': '#333333',
            'font': ('Arial', 10)
        },
        'Treeview': {
            'background': '#ffffff',
            'foreground': '#333333',
            'fieldbackground': '#ffffff',
            'font': ('Arial', 10)
        },
        'Treeview.Heading': {
            'background': '#003366',
            'foreground': 'white',
            'font': ('Arial', 10, 'bold')
        }
    }
    
    for widget, properties in style.items():
        root.style.configure(widget, **properties)
        
    # Additional style configurations
    root.style.map('TButton',
        background=[('active', '#004488'), ('disabled', '#cccccc')],
        foreground=[('disabled', '#888888')]
    )
    
    root.style.map('Treeview.Heading',
        background=[('active', '#004488')]
    )