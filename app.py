
from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TrustVault | Secure Documents</title>

        <style>
            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: #f4f7fb;
                color: #1e293b;
            }

            header {
                background: #172554;
                color: white;
                padding: 22px 8%;
            }

            header h1 {
                margin: 0;
                font-size: 26px;
            }

            header p {
                margin-bottom: 0;
                color: #cbd5e1;
            }

            main {
                max-width: 1000px;
                margin: 40px auto;
                padding: 0 20px;
            }

            .welcome {
                background: white;
                padding: 28px;
                border-radius: 12px;
                margin-bottom: 24px;
            }

            .welcome h2 {
                margin-top: 0;
                color: #172554;
            }

            .cards {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 18px;
            }

            .card {
                background: white;
                padding: 24px;
                border-radius: 12px;
                border: 1px solid #e2e8f0;
            }

            .card h3 {
                margin-top: 0;
                color: #1d4ed8;
            }

            .status {
                display: inline-block;
                background: #dbeafe;
                color: #1e40af;
                padding: 6px 10px;
                border-radius: 20px;
                font-size: 13px;
            }

            footer {
                text-align: center;
                color: #64748b;
                padding: 30px;
            }
        </style>
    </head>

    <body>
        <header>
            <h1>TrustVault</h1>
            <p>Secure document sharing with accountability</p>
        </header>

        <main>
            <section class="welcome">
                <h2>Welcome to TrustVault!</h2>
                <p>
                    A secure place to manage documents and control
                    who can access them.
                </p>
                <span class="status">Development version</span>
            </section>

            <section class="cards">
                <div class="card">
                    <h3>My Documents</h3>
                    <p>Your documents will appear here after secure
                    upload functionality is implemented.</p>
                </div>

                <div class="card">
                    <h3>Access Permissions</h3>
                    <p>Document owners will be able to grant and
                    revoke access to named users.</p>
                </div>

                <div class="card">
                    <h3>Audit Trail</h3>
                    <p>We will record document activity and
                    permission changes.</p>
                </div>
            </section>
        </main>

        <footer>
            TrustVault &copy; 2026
        </footer>
    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(debug=True)

