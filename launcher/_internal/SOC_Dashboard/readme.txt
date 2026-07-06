SOC_Dashboard/
│
├── app/
│   │
│   ├── main.py
│   │
│   ├── templates/
│   │   └── dashboard.html
│   │
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css
│   │   │
│   │   ├── js/
│   │   │   └── dashboard.js
│   │   │
│   │   ├── icons/
│   │   │
│   │   └── images/
│   │
│   └── api/
│       └── dashboard_api.py
│
├── requirements.txt
│
└── run.py

>main.py
    Main FastAPI application starts here.Think of it as:Dashboard Brain

>templates/dashboard.html
    Everything visible on screen:
                cards
                charts
                buttons
                tables
                sidebar      is inside this file.

>static/css/style.css
    colors
    spacing
    borders
    glow effects
    fonts
    animations

>static/js/dashboard.js
    Controls:   charts
                API calls
                table updates
                refresh logic
                scan button
                filters

>api/dashboard_api.py
    /api/alerts
    /api/system-info
    /api/charts

>requirements.txt
Stores all Python packages.

>run.py
Starts the dashboard server.


Commands:

> python -m venv venv
> venv\Scripts\activate
> pip install fastapi uvicorn jinja2 python-multipart
> python.exe -m pip install --upgrade pip
> pip freeze > requirements.txt
> python run.py
> python launcher.py
> uvicorn app.main:app --reload
>pip install --no-index --find-links=offline_packages -r requirements.txt