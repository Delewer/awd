from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import socket, ssl, requests, datetime, dns.resolver, math, io
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


def dashboard(request):
    result = None
    history = request.session.get("history", [])

    if request.method == "POST":
        host = request.POST.get("host", "").strip()
        findings = []
        score = 100

        # 1. Porturi
        open_ports = []
        for p in [21, 22, 25, 80, 443]:
            try:
                s = socket.socket()
                s.settimeout(1)
                if s.connect_ex((host, p)) == 0:
                    open_ports.append(p)
                s.close()
            except:
                pass

        if open_ports:
            risky = [p for p in open_ports if p in (21, 22, 25)]
            findings.append({
                "section": "Internet Exposure",
                "status": "⚠️" if risky else "✅",
                "details": f"Porturi deschise: {open_ports}",
                "recommendation": "Închide porturile inutile și activează firewall."
            })
            if risky:
                score -= 15
        else:
            findings.append({
                "section": "Internet Exposure",
                "status": "✅",
                "details": "Nu s-au găsit porturi comune expuse.",
                "recommendation": "OK"
            })

        # 2. TLS & Certificat
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(2)
                s.connect((host, 443))
                cert = s.getpeercert()
                version = s.version()

            not_after = cert.get("notAfter")
            if not_after:
                exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - datetime.datetime.utcnow()).days
                findings.append({
                    "section": "TLS & Certificate",
                    "status": "✅" if days_left > 30 else "⚠️",
                    "details": f"Certificat valid ({days_left} zile rămase)",
                    "recommendation": "Reînnoiește certificatul cu cel puțin 30 zile înainte de expirare."
                })
                if days_left <= 30:
                    score -= 10
            legacy = version in ("TLSv1", "TLSv1.1")
            findings.append({
                "section": "TLS & Certificate",
                "status": "⚠️" if legacy else "✅",
                "details": f"Versiune negociată: {version}",
                "recommendation": "Dezactivează TLS 1.0/1.1; păstrează doar TLS 1.2/1.3."
            })
            if legacy:
                score -= 10
        except:
            findings.append({
                "section": "TLS & Certificate",
                "status": "❌",
                "details": "Certificat TLS invalid sau lipsă.",
                "recommendation": "Configurează un certificat valid (ex: Let's Encrypt)."
            })
            score -= 20

        # 3. Web Headers
        try:
            r = requests.get(f"https://{host}", timeout=3)
            h = {k.lower(): v for k, v in r.headers.items()}
            banner = h.get("server", "necunoscut")

            findings.append({
                "section": "Server Banner",
                "status": "ℹ️",
                "details": f"Server: {banner}",
                "recommendation": "Ascunde versiunea software-ului pentru a reduce footprint-ul CVE."
            })

            if "strict-transport-security" in h:
                findings.append({"section": "Web Headers", "status": "✅", "details": "HSTS activat", "recommendation": "OK"})
            else:
                findings.append({"section": "Web Headers", "status": "❌", "details": "HSTS lipsă", "recommendation": "Activează HSTS."})
                score -= 10

            if "content-security-policy" in h:
                findings.append({"section": "Web Headers", "status": "✅", "details": "CSP prezent", "recommendation": "OK"})
            else:
                findings.append({"section": "Web Headers", "status": "❌", "details": "CSP lipsă", "recommendation": "Adaugă CSP pentru protecție XSS."})
                score -= 10

            if h.get("x-frame-options", "").lower() in ("deny", "sameorigin"):
                findings.append({"section": "Web Headers", "status": "✅", "details": "X-Frame-Options setat", "recommendation": "OK"})
            else:
                findings.append({"section": "Web Headers", "status": "⚠️", "details": "X-Frame-Options lipsă", "recommendation": "Adaugă X-Frame-Options."})
                score -= 5
        except:
            findings.append({
                "section": "Web Headers",
                "status": "❌",
                "details": "Nu s-au putut prelua headerele.",
                "recommendation": "Asigură-te că site-ul răspunde corect pe HTTPS."
            })
            score -= 15

        # 4. Email Auth (SPF simplu)
        try:
            domain_parts = host.split(".")
            domain = ".".join(domain_parts[-2:])
            answers = dns.resolver.resolve(domain, "TXT")
            spf_records = [r.to_text() for r in answers if "spf" in r.to_text().lower()]
            if spf_records:
                findings.append({
                    "section": "Email Auth",
                    "status": "✅",
                    "details": f"SPF record: {spf_records}",
                    "recommendation": "OK"
                })
            else:
                findings.append({
                    "section": "Email Auth",
                    "status": "❌",
                    "details": "Nu există SPF",
                    "recommendation": "Adaugă SPF pentru a preveni spoofing email."
                })
                score -= 10
        except:
            findings.append({
                "section": "Email Auth",
                "status": "❌",
                "details": "Nu s-a putut verifica SPF.",
                "recommendation": "Configurează SPF/DKIM/DMARC în DNS."
            })
            score -= 10

        # Scor general + cerc SVG
        if score >= 80:
            color = "🟢 Conform"
            bar_class = "progress-bar bg-success"
        elif score >= 60:
            color = "🟠 Parțial conform"
            bar_class = "progress-bar bg-warning"
        else:
            color = "🔴 Neconform"
            bar_class = "progress-bar bg-danger"

        radius = 52
        circumference = 2 * math.pi * radius
        offset = circumference - (circumference * score / 100)

        result = {
            "host": host,
            "score": score,
            "color": color,
            "bar_class": bar_class,
            "findings": findings,
            "date": datetime.datetime.now().strftime("%d.%m.%Y"),
            "circumference": circumference,
            "offset": offset,
        }

        # salvăm în sesiune pentru export și istoric
        request.session["last_result"] = result
        history.append({"date": result["date"], "score": result["score"]})
        request.session["history"] = history

    return render(request, "dashboard.html", {"result": result, "history": history})


# Export JSON
def export_json(request):
    result = request.session.get("last_result")
    if not result:
        return JsonResponse({"error": "Nu există raport disponibil."}, status=400)
    return JsonResponse(result)


# Export PDF
def export_pdf(request):
    result = request.session.get("last_result")
    if not result:
        return HttpResponse("Nu există raport disponibil.", status=400)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(f"📅 Data scanării: {result['date']}", styles["Normal"]))
    elements.append(Paragraph(f"🔒 Domeniu/IP: {result['host']}", styles["Normal"]))
    elements.append(Paragraph(f"Scor general: {result['color']} ({result['score']}%)", styles["Normal"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Rezultate detaliate:</b>", styles["Heading2"]))
    for f in result["findings"]:
        elements.append(Paragraph(f"<b>{f['section']} – {f['status']}</b>", styles["Heading3"]))
        elements.append(Paragraph(f"Detalii: {f['details']}", styles["Normal"]))
        elements.append(Paragraph(f"Recomandare: {f['recommendation']}", styles["Normal"]))
        elements.append(Spacer(1, 8))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(
        "Disclaimer: Acest raport are scop informativ și educativ. "
        "Nu înlocuiește un audit extern autorizat conform HG nr. 49/2025.",
        styles["Italic"]
    ))

    doc.build(elements)
    buffer.seek(0)
    response = HttpResponse(buffer, content_type="application/pdf")
    response["Content-Disposition"] = 'attachment; filename=\"raport_audit.pdf\"'
    return response

# Compliance Checklist
def checklist(request):
    score = None
    if request.method == "POST":
        answers = request.POST
        total = 0
        ok = 0
        for key, val in answers.items():
            if val in ("yes", "no"):
                total += 1
                if val == "yes":
                    ok += 1
        score = int((ok / total) * 100) if total else 0

    return render(request, "checklist.html", {"score": score})

# Incident Reporter (Art. 12 – trei pași)
def incident_report(request):
    step = int(request.GET.get("step", 1))
    data = request.session.get("incident", {})

    if request.method == "POST":
        for k, v in request.POST.items():
            if k != "csrfmiddlewaretoken":
                data[k] = v
        request.session["incident"] = data
        step += 1
        if step > 3:
            step = 3

    return render(request, "incident.html", {"step": step, "data": data})
