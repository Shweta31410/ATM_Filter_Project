// static/main.js
const socket = io();

const totalEl = document.getElementById('total');
const forwardedEl = document.getElementById('forwarded');
const droppedEl = document.getElementById('dropped');
const dhEl = document.getElementById('dropped_header');
const dpEl = document.getElementById('dropped_policer');
const dplEl = document.getElementById('dropped_payload');
const finalResultDiv = document.getElementById('finalResult');

const ctx = document.getElementById('barChart').getContext('2d');
const barChart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: ['header','policer','payload'],
        datasets: [{
            label: 'Dropped cells',
            data: [0,0,0],
            backgroundColor: ['#e74c3c','#f39c12','#9b59b6']
        }]
    },
    options: {
        responsive: true,
        animation: false,
        scales: { y: { beginAtZero: true } }
    }
});

document.getElementById('startBtn').addEventListener('click', () => {
    finalResultDiv.innerHTML = "";
    const duration = parseFloat(document.getElementById('duration').value) || 5;
    const rate = parseFloat(document.getElementById('rate').value) || 200;
    const mal_frac = parseFloat(document.getElementById('mal_frac').value) || 0.12;
    const seedVal = document.getElementById('seed').value;
    const seed = seedVal ? parseInt(seedVal) : null;

    // reset display
    totalEl.textContent = forwardedEl.textContent = droppedEl.textContent = 0;
    dhEl.textContent = dpEl.textContent = dplEl.textContent = 0;
    barChart.data.datasets[0].data = [0,0,0];
    barChart.update();

    socket.emit('start_sim', { duration, rate, mal_frac, seed });
});

socket.on('sim_update', (stats) => {
    totalEl.textContent = stats.total || 0;
    forwardedEl.textContent = stats.forwarded || 0;
    droppedEl.textContent = stats.dropped || 0;
    dhEl.textContent = stats.dropped_header || 0;
    dpEl.textContent = stats.dropped_policer || 0;
    dplEl.textContent = stats.dropped_payload || 0;

    barChart.data.datasets[0].data = [
        stats.dropped_header || 0,
        stats.dropped_policer || 0,
        stats.dropped_payload || 0
    ];
    barChart.update();
});

socket.on('sim_done', (final) => {
    finalResultDiv.innerHTML = `<b>Simulation finished.</b>
      Total=${final.total || 0}, Forwarded=${final.forwarded || 0}, Dropped=${final.dropped || 0}
      <br>False positive rate: ${ (final.false_positive_rate || 0).toFixed(4) }
      , False negative rate: ${ (final.false_negative_rate || 0).toFixed(4) }`;
});

socket.on('sim_error', (d) => alert(d.msg));
socket.on('sim_started', (d) => console.log(d.msg));
