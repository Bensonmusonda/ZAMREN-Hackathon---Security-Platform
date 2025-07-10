const API_BASE_URL = 'http://localhost:8000'; // Your FastAPI backend URL

// Function to fetch data from a given endpoint
async function fetchData(endpoint) {
    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error(`Could not fetch data from ${endpoint}:`, error);
        return null;
    }
}

// Function to update summary numbers
async function updateSummaryCounts() {
    const threatCounts = await fetchData('/threat-counts');

    if (threatCounts) {
        // Network Monitoring
        // The 'total-alerts' div is showing total_network_threats
        document.getElementById('suspiciousIpCount').textContent = `Suspicious IP Attempts: ${threatCounts.suspicious_ip_attempts}`;
        document.getElementById('bruteForceCount').textContent = `Brute Force Attacks: ${threatCounts.brute_force_attacks}`;
        document.getElementById('malwareCount').textContent = `Malware Detections: ${threatCounts.malware_detections}`;
        document.getElementById('pendingAlertsCount').textContent = `Pending Alerts: ${threatCounts.pending_threats}`;
        document.getElementById('totalNetworkAlertsCount').textContent = `Total Alerts: ${threatCounts.total_network_threats}`; // Added "Total Alerts:" for clarity

        // Email Traffic
        document.getElementById('totalEmailsCount').textContent = `Total Emails: ${threatCounts.total_emails_received}`; // Updated to reflect correct ID and clearer text
        document.getElementById('spamEmailsCount').textContent = `Spam Emails: ${threatCounts.spam_emails_detected}`;

        // SMS Traffic
        document.getElementById('totalSmsCount').textContent = `Total SMS: ${threatCounts.total_sms_received}`; // Updated to reflect correct ID and clearer text
        document.getElementById('spamSmsCount').textContent = `Spam SMS: ${threatCounts.sms_spam_detected}`;
    }
}

// Function to create a scrollable table from data
function createTable(data, containerId, columns) {
    const container = document.querySelector(`#${containerId} .table-container`);
    if (!container) {
        console.error(`Table container with ID ${containerId} .table-container not found.`);
        return;
    }

    // Clear previous content
    container.innerHTML = '';

    if (!data || data.length === 0) {
        container.textContent = 'No data available.';
        return;
    }

    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const tbody = document.createElement('tbody');

    // Create table header
    const headerRow = document.createElement('tr');
    columns.forEach(col => {
        const th = document.createElement('th');
        th.textContent = col.header;
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    // Create table body
    data.forEach(item => {
        const row = document.createElement('tr');
        columns.forEach(col => {
            const td = document.createElement('td');
            let value = item[col.field];
            if (col.format) {
                value = col.format(value);
            }
            td.textContent = value;
            row.appendChild(td);
        });
        tbody.appendChild(row);
    });
    table.appendChild(tbody);
    container.appendChild(table);
}

// Function to update lists/tables
async function updateLists() {
    // Recent Threats (Security Insights)
    const recentThreats = await fetchData('/threats/recent');

    // Recent Email Logs
    const recentEmailLogs = await fetchData('/raw-email-logs');
    if (recentEmailLogs) {
        const emailLogColumns = [
            { header: 'Timestamp', field: 'received_timestamp', format: (ts) => new Date(ts).toLocaleString() },
            { header: 'Sender', field: 'sender' },
            { header: 'Subject', field: 'subject' },
            { header: 'Status', field: 'detection_status' },
        ];
        createTable(recentEmailLogs, 'recentEmailLogsContainer', emailLogColumns);
    }

    // Recent SMS Logs
    const recentSmsLogs = await fetchData('/raw-sms-logs');
    if (recentSmsLogs) {
        const smsLogColumns = [
            { header: 'Timestamp', field: 'timestamp', format: (ts) => new Date(ts).toLocaleString() },
            { header: 'Sender', field: 'sender_number' },
            { header: 'Content', field: 'message_content' },
            { header: 'Status', field: 'detection_status' },
        ];
        createTable(recentSmsLogs, 'recentSmsLogsContainer', smsLogColumns);
    }

    // Recent Network Threats (filtered from all recent threats)
    if (recentThreats) {
        const networkThreatsOnly = recentThreats.filter(threat => threat.source_type === "network_ids");
        const networkThreatColumns = [
            { header: 'Timestamp', field: 'timestamp', format: (ts) => new Date(ts).toLocaleString() },
            { header: 'Threat Type', field: 'threat_type' },
            { header: 'Source IP', field: 'source_identifier' },
            { header: 'Severity', field: 'severity' },
        ];
        createTable(networkThreatsOnly, 'recentNetworkThreatsContainer', networkThreatColumns);
    }

    // Security Insights Table (assuming you want a table here)
    if (recentThreats) { // Using all recent threats for security insights
        const securityInsightsColumns = [
            { header: 'Timestamp', field: 'timestamp', format: (ts) => new Date(ts).toLocaleString() },
            { header: 'Source', field: 'source_type', format: (type) => type.replace('_', ' ').toUpperCase() },
            { header: 'Threat', field: 'threat_type' },
            { header: 'Source ID', field: 'source_identifier' },
            { header: 'Severity', field: 'severity' },
        ];
        // Note: You had no #security-insights .table-container in the JS's createTable call.
        // Assuming you want the main recentThreats in the security-insights section.
        createTable(recentThreats, 'security-insights', securityInsightsColumns);
    }
}

// Initial data load and periodic refresh
document.addEventListener('DOMContentLoaded', () => {
    updateSummaryCounts();
    updateLists();

    // Optional: Refresh data every 30 seconds
    setInterval(() => {
        updateSummaryCounts();
        updateLists();
    }, 30000); // Refresh every 30 seconds
});