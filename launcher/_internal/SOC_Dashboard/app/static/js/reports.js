/* =========================================
   LOAD REPORTS
========================================= */

async function loadReports(){

    const response =
    await fetch("/api/reports");

    const reports =
    await response.json();

    const container =
    document.querySelector(
        ".reports-list"
    );

    container.innerHTML = "";

    reports.forEach(report => {

        const severity =
        report.severity.toLowerCase();

        const card =
        document.createElement("div");

        card.className =
        `report-card ${severity}`;

        card.innerHTML = `

            <div class="report-top">

                <div>

                    <h2>

                        ${report.case_id}

                    </h2>

                    <span>

                        ${report.title}

                    </span>

                </div>

                <div class="
                    severity-tag
                    ${severity}
                ">

                    ${report.severity}

                </div>

            </div>

            <div class="report-meta">

                <span>

                    Analyst:
                    ${report.analyst}

                </span>

                <span>

                    Generated:
                    ${report.generated}

                </span>

                <span>

                    Status:
                    ${report.status}

                </span>

            </div>

            <div class="report-actions">

                <button>

                    View Report

                </button>

                <button>

                    Download PDF

                </button>

            </div>
        `;

        container.appendChild(card);
    });
}

/* =========================================
   INITIAL LOAD
========================================= */

loadReports();