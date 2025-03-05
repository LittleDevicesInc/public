#!/usr/bin/env python3
"""
Simple test script to verify PDF generation with reportlab.
"""

import sys

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet

    # Create a test PDF
    doc = SimpleDocTemplate("test.pdf", pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Add a title
    elements.append(Paragraph("PDF Test Document", styles['Heading1']))
    elements.append(Spacer(1, 12))

    # Add some text
    elements.append(Paragraph("This is a test document to verify reportlab is working correctly.", styles['Normal']))
    elements.append(Spacer(1, 12))

    # Add a table
    data = [
        ["Column 1", "Column 2", "Column 3"],
        ["Data 1", "Data 2", "Data 3"],
        ["Data 4", "Data 5", "Data 6"]
    ]

    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))

    elements.append(table)

    # Build the document
    doc.build(elements)

    print("PDF successfully generated: test.pdf")
    sys.exit(0)

except ImportError as e:
    print(f"ImportError: {str(e)}")
    print("reportlab is not installed or cannot be imported.")
    print("Try: pip install reportlab")
    sys.exit(1)

except Exception as e:
    print(f"Error generating PDF: {str(e)}")
    import traceback
    traceback.print_exc()
    sys.exit(2)