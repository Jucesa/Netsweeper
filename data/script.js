const tableBody = document.getElementById("tableBody");
const scanBtn = document.getElementById("scanBtn");
const totalHosts = document.getElementById("totalHosts");

async function loadDevices() {

    tableBody.innerHTML = "";

    const response = await fetch("/devices");

    const devices = await response.json();

    totalHosts.innerHTML =
        `Hosts encontrados: ${devices.length}`;

    devices.forEach(device => {

        const row = document.createElement("tr");

        if (device.vulnerable) {
            row.classList.add("vulnerable");
        }

        row.innerHTML = `
            <td>${device.ip}</td>

            <td class="online">
                ONLINE
            </td>

            <td>${device.ports}</td>

            <td>
                ${
                    device.vulnerable
                    ? '<span class="danger-status">ALTO</span>'
                    : '<span class="safe-status">BAIXO</span>'
                }
            </td>
        `;

        tableBody.appendChild(row);
    });
}

scanBtn.addEventListener("click", async () => {

    scanBtn.innerHTML = "Escaneando...";

    await fetch("/scan");

    await loadDevices();

    scanBtn.innerHTML = "Nova Varredura";
});

loadDevices();