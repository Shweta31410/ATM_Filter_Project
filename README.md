# ATM Filter Project

This project simulates an ATM network traffic filter system. The system monitors requests passing between ATM terminals and the central banking network, and it identifies and blocks suspicious or unwanted packets.

## Features

* A simple ATM simulation module
* Packet filtering logic to detect unusual patterns
* Web-based dashboard to display logs and filtering results
* Real-time interaction and visual representation

## Project Structure

* `app.py` - Main Flask application
* `atm_sim.py` - ATM request simulation
* `filtering.py` - Filtering logic implementation
* `templates/index.html` - Frontend HTML interface
* `static/` - Contains CSS and JavaScript files

## How to Run

1. Install dependencies:

```
pip install -r requirements.txt
```

2. Run the app:

```
python app.py
```

3. Open your browser and navigate to:

```
http://127.0.0.1:5000/
```

## Future Enhancements

* Add user authentication
* Create advanced packet pattern rules
* Store logs in a database instead of memory

## License

This project is for educational purposes only.
