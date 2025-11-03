# app.py
import time, random, threading
from collections import defaultdict
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from filtering import ATMCell, HeaderRule, PayloadRule, ATMFilter

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

# default rules used unless user changes
DEFAULT_HEADER_DENY = [(1,30)]
DEFAULT_SIGS = ["BADSIG_"]
DEFAULT_POLICER_CFG = {
    (0,10): (50.0, 20.0),
    (2,40): (30.0, 10.0)
}

# keep a reference to the running thread so we don't run multiple
sim_thread = None
sim_lock = threading.Lock()

@app.route('/')
def index():
    return render_template('index.html')

def traffic_generator(duration_sec, total_rate, malicious_fraction, seed=None):
    if seed is not None:
        random.seed(seed)
    t = 0.0
    dt = 1.0 / total_rate
    while t < duration_sec:
        vpi = random.choice([0,1,2])
        vci = random.choice([10,20,30,40])
        is_mal = random.random() < malicious_fraction
        payload = "NORMALDATA"
        if is_mal:
            payload = "BADSIG_" + str(random.randint(0,999))
        yield t, ATMCell(vpi, vci, payload, is_mal)
        t += dt

def run_simulation_emit(duration, rate, mal_frac, header_deny, sigs, policer_cfg, update_interval=0.5, seed=None):
    """
    Run the simulation and emit periodic stats via SocketIO.
    update_interval: seconds between socket emits (aggregates while running)
    """
    atm_filter = ATMFilter(HeaderRule(header_deny), PayloadRule(sigs), policer_cfg)
    stats = defaultdict(int)
    now_base = time.time()
    last_emit_time = now_base
    batch_count = 0

    for t_offset, cell in traffic_generator(duration, rate, mal_frac, seed):
        now = now_base + t_offset
        stats['total'] += 1
        if cell.is_malicious: stats['mal_total'] += 1
        else: stats['legit_total'] += 1

        action, reason = atm_filter.process(cell, now)
        if action == "drop":
            stats['dropped'] += 1
            stats[f'dropped_{reason}'] += 1
            if cell.is_malicious: stats['mal_dropped'] += 1
            else: stats['legit_dropped'] += 1
        else:
            stats['forwarded'] += 1
            if cell.is_malicious: stats['mal_forwarded'] += 1
            else: stats['legit_forwarded'] += 1

        # periodically emit aggregated stats so front-end gets live update
        if time.time() - last_emit_time >= update_interval:
            emit_stats = {
                'total': stats.get('total',0),
                'forwarded': stats.get('forwarded',0),
                'dropped': stats.get('dropped',0),
                'dropped_header': stats.get('dropped_header',0),
                'dropped_policer': stats.get('dropped_policer',0),
                'dropped_payload': stats.get('dropped_payload',0),
                'mal_total': stats.get('mal_total',0),
                'mal_forwarded': stats.get('mal_forwarded',0),
                'mal_dropped': stats.get('mal_dropped',0),
                'legit_total': stats.get('legit_total',0),
                'legit_forwarded': stats.get('legit_forwarded',0),
                'legit_dropped': stats.get('legit_dropped',0),
            }
            socketio.emit('sim_update', emit_stats)
            last_emit_time = time.time()
            batch_count += 1

    # final emit
    final = dict(stats)
    final['false_positive_rate'] = (final.get('legit_dropped',0)/final.get('legit_total',1)) if final.get('legit_total') else 0.0
    final['false_negative_rate'] = (final.get('mal_forwarded',0)/final.get('mal_total',1)) if final.get('mal_total') else 0.0
    socketio.emit('sim_done', final)

@socketio.on('start_sim')
def handle_start_sim(data):
    """
    data = {
      duration: float,
      rate: float,
      mal_frac: float,
      seed: int | None
    }
    """
    global sim_thread
    with sim_lock:
        if sim_thread and sim_thread.is_alive():
            emit('sim_error', {'msg': 'Simulation already running.'})
            return
        duration = float(data.get('duration',5.0))
        rate = float(data.get('rate',200.0))
        mal_frac = float(data.get('mal_frac',0.12))
        seed = data.get('seed', None)
        # You could allow user to change rules via UI; here we use defaults
        header_deny = DEFAULT_HEADER_DENY
        sigs = DEFAULT_SIGS
        policer_cfg = DEFAULT_POLICER_CFG

        sim_thread = threading.Thread(target=run_simulation_emit,
                                      args=(duration, rate, mal_frac, header_deny, sigs, policer_cfg, 0.5, seed),
                                      daemon=True)
        sim_thread.start()
        emit('sim_started', {'msg':'Simulation started'})

@socketio.on('connect')
def on_connect():
    emit('connected', {'msg':'Connected to server'})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
