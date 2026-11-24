"""
Generate high-resolution, professional architecture diagrams:
1. /Users/arpit/toa_project/images/existing_architecture.png
2. /Users/arpit/toa_project/images/proposed_architecture.png
"""

import os
from PIL import Image, ImageDraw, ImageFont

FONT_PATH = "/System/Library/Fonts/Supplemental/Arial.ttf"
if not os.path.exists(FONT_PATH):
    FONT_PATH = "/System/Library/Fonts/Helvetica.ttc"

def get_font(size, bold=False):
    try:
        return ImageFont.truetype(FONT_PATH, size)
    except Exception:
        return ImageFont.load_default()

def draw_rounded_card(draw, xy, fill, outline, radius=12, width=2):
    x0, y0, x1, y1 = xy
    draw.rounded_rectangle([x0, y0, x1, y1], radius=radius, fill=fill, outline=outline, width=width)

def draw_arrow(draw, start, end, fill="#475569", width=3, arrow_size=10):
    x0, y0 = start
    x1, y1 = end
    draw.line([(x0, y0), (x1, y1)], fill=fill, width=width)
    
    # Arrowhead
    if x0 == x1: # Vertical
        if y1 > y0: # Downward
            points = [(x1, y1), (x1 - arrow_size, y1 - arrow_size * 1.4), (x1 + arrow_size, y1 - arrow_size * 1.4)]
        else: # Upward
            points = [(x1, y1), (x1 - arrow_size, y1 + arrow_size * 1.4), (x1 + arrow_size, y1 + arrow_size * 1.4)]
    elif y0 == y1: # Horizontal
        if x1 > x0: # Rightward
            points = [(x1, y1), (x1 - arrow_size * 1.4, y1 - arrow_size), (x1 - arrow_size * 1.4, y1 + arrow_size)]
        else: # Leftward
            points = [(x1, y1), (x1 + arrow_size * 1.4, y1 - arrow_size), (x1 + arrow_size * 1.4, y1 + arrow_size)]
    else:
        # Default simple end
        points = [(x1, y1), (x1 - arrow_size, y1 - arrow_size), (x1 + arrow_size, y1 - arrow_size)]
    draw.polygon(points, fill=fill)

def render_existing_architecture(out_path):
    # Dimensions: 1400 x 950
    W, H = 1400, 950
    img = Image.new("RGB", (W, H), "#F8FAFC")
    draw = ImageDraw.Draw(img)

    f_title = get_font(32)
    f_sub = get_font(18)
    f_card_title = get_font(20)
    f_body = get_font(15)
    f_badge = get_font(14)

    # Header Banner
    draw.rectangle([0, 0, W, 90], fill="#0F172A")
    draw.text((W//2, 32), "Existing Architecture: Traditional Compiler & Naive AI Workflow", font=f_title, fill="#FFFFFF", anchor="mm")
    draw.text((W//2, 68), "Unverified, vulnerable trial-and-error debugging loop commonly used by novice students", font=f_sub, fill="#94A3B8", anchor="mm")

    # Step 1: Novice Source Code
    c1 = (100, 150, 420, 320)
    draw_rounded_card(draw, c1, fill="#FFFFFF", outline="#CBD5E1", radius=14, width=2)
    draw.rectangle([100, 150, 420, 200], fill="#3B82F6")
    draw.text((260, 175), "1. Novice Source Code", font=f_card_title, fill="#FFFFFF", anchor="mm")
    lines1 = [
        "• Student writes C++, C, or Python code",
        "• Lacks mental model of compiler grammar",
        "• Often contains simple typos or syntax slips",
        "• Unaware of memory safety or CWE risks"
    ]
    y = 220
    for l in lines1:
        draw.text((120, y), l, font=f_body, fill="#334155")
        y += 24

    # Arrow 1 -> 2
    draw_arrow(draw, (420, 235), (520, 235), fill="#64748B", width=4)

    # Step 2: Local Host Compiler / Interpreter
    c2 = (520, 150, 880, 320)
    draw_rounded_card(draw, c2, fill="#FFFFFF", outline="#CBD5E1", radius=14, width=2)
    draw.rectangle([520, 150, 880, 200], fill="#6366F1")
    draw.text((700, 175), "2. Host Compiler / Interpreter", font=f_card_title, fill="#FFFFFF", anchor="mm")
    lines2 = [
        "• GCC, Clang++, or CPython on host",
        "• Validates formal context-free grammar",
        "• Emits strict spatial caret diagnostics",
        "• No isolated sandbox protection"
    ]
    y = 220
    for l in lines2:
        draw.text((540, y), l, font=f_body, fill="#334155")
        y += 24

    # Arrow 2 -> 3
    draw_arrow(draw, (880, 235), (980, 235), fill="#EF4444", width=4)

    # Step 3: Cryptic Compiler Diagnostics
    c3 = (980, 150, 1300, 320)
    draw_rounded_card(draw, c3, fill="#FEF2F2", outline="#F87171", radius=14, width=2)
    draw.rectangle([980, 150, 1300, 200], fill="#EF4444")
    draw.text((1140, 175), "3. Terse Compiler Error", font=f_card_title, fill="#FFFFFF", anchor="mm")
    lines3 = [
        "• 'expected ';' after expression'",
        "• 'cannot initialize int with const char*'",
        "• 'ld: symbols not found for arm64'",
        "• Unintelligible compiler jargon"
    ]
    y = 220
    for l in lines3:
        draw.text((1000, y), l, font=f_body, fill="#991B1B")
        y += 24

    # Arrow Down from 3 to 4
    draw_arrow(draw, (1140, 320), (1140, 420), fill="#EF4444", width=4)

    # Step 4: Novice Confusion & StackOverflow Guesswork
    c4 = (980, 420, 1300, 590)
    draw_rounded_card(draw, c4, fill="#FFFBEB", outline="#FCD34D", radius=14, width=2)
    draw.rectangle([980, 420, 1300, 470], fill="#F59E0B")
    draw.text((1140, 445), "4. Novice Confusion", font=f_card_title, fill="#FFFFFF", anchor="mm")
    lines4 = [
        "• Student unable to interpret message",
        "• Searches Stack Overflow verbatim",
        "• Wastes hours on trial-and-error",
        "• Frustration and cognitive overload"
    ]
    y = 490
    for l in lines4:
        draw.text((1000, y), l, font=f_body, fill="#92400E")
        y += 24

    # Arrow Left from 4 to 5
    draw_arrow(draw, (980, 505), (880, 505), fill="#64748B", width=4)

    # Step 5: Copy-Paste to Unconstrained Cloud AI
    c5 = (520, 420, 880, 590)
    draw_rounded_card(draw, c5, fill="#FFFFFF", outline="#CBD5E1", radius=14, width=2)
    draw.rectangle([520, 420, 880, 470], fill="#8B5CF6")
    draw.text((700, 445), "5. Unconstrained Cloud AI", font=f_card_title, fill="#FFFFFF", anchor="mm")
    lines5 = [
        "• Student pastes code into ChatGPT / Copilot",
        "• Requires constant internet connection",
        "• Cloud AI guesses from raw text only",
        "• Has no access to compiler AST or rules"
    ]
    y = 490
    for l in lines5:
        draw.text((540, y), l, font=f_body, fill="#334155")
        y += 24

    # Arrow Left from 5 to 6
    draw_arrow(draw, (520, 505), (420, 505), fill="#EF4444", width=4)

    # Step 6: Hallucinated & Insecure Fix
    c6 = (100, 420, 420, 590)
    draw_rounded_card(draw, c6, fill="#FEF2F2", outline="#F87171", radius=14, width=2)
    draw.rectangle([100, 420, 420, 470], fill="#DC2626")
    draw.text((260, 445), "6. Unverified Code Output", font=f_card_title, fill="#FFFFFF", anchor="mm")
    lines6 = [
        "• Hallucinates non-existent variables",
        "• Suggests insecure C code (gets, strcpy)",
        "• Patches fail to compile or break tests",
        "• Student applies unverified patch"
    ]
    y = 490
    for l in lines6:
        draw.text((120, y), l, font=f_body, fill="#991B1B")
        y += 24

    # Feedback Loop: From 6 back up to 2
    # Polyline: (260, 420) -> (260, 370) -> (700, 370) -> (700, 320)
    draw.line([(260, 420), (260, 370), (700, 370)], fill="#DC2626", width=4)
    draw_arrow(draw, (700, 370), (700, 320), fill="#DC2626", width=4)
    draw_rounded_card(draw, (410, 350, 550, 390), fill="#DC2626", outline="#DC2626", radius=6)
    draw.text((480, 370), "Fails Again!", font=f_badge, fill="#FFFFFF", anchor="mm")

    # Bottom Summary Callout Box
    draw_rounded_card(draw, (100, 660, 1300, 880), fill="#F1F5F9", outline="#94A3B8", radius=14, width=2)
    draw.text((130, 690), "Key Limitations of the Existing Architecture:", font=f_card_title, fill="#0F172A")
    flaws = [
        "❌ Zero Sandboxing: Code executes directly on the host, exposing the machine to runaway loops and crashes.",
        "❌ Cryptic Jargon: Compiler diagnostics are designed for language standards, not for teaching beginners.",
        "❌ AI Hallucinations: General cloud LLMs invent fake variables and logic because they lack compiler AST facts.",
        "❌ Security Blindness: Cloud AI routinely fixes syntax while ignoring fatal buffer overflows (CWE-120) and command injection (CWE-78).",
        "❌ Unverified Fixes: No closed-loop re-compilation or test execution before presenting code to the student."
    ]
    y = 730
    for fl in flaws:
        draw.text((130, y), fl, font=f_body, fill="#475569")
        y += 28

    img.save(out_path, "PNG", dpi=(300, 300))
    print(f"Existing architecture diagram saved to {out_path}")

def render_proposed_architecture(out_path):
    # Dimensions: 1500 x 1150
    W, H = 1500, 1150
    img = Image.new("RGB", (W, H), "#F8FAFC")
    draw = ImageDraw.Draw(img)

    f_title = get_font(30)
    f_sub = get_font(17)
    f_card_title = get_font(18)
    f_body = get_font(14)
    f_badge = get_font(13)

    # Header Banner
    draw.rectangle([0, 0, W, 85], fill="#1E293B")
    draw.text((W//2, 30), "Proposed Architecture: Multi-Language Compiler Debugger & Security Framework", font=f_title, fill="#FFFFFF", anchor="mm")
    draw.text((W//2, 62), "Closed-loop, sandboxed pedagogical automated repair engine with 10 defense layers & 9-stage CWE scanner", font=f_sub, fill="#94A3B8", anchor="mm")

    # Step 1: User Interface
    c1 = (60, 130, 350, 320)
    draw_rounded_card(draw, c1, fill="#FFFFFF", outline="#3B82F6", radius=12, width=2)
    draw.rectangle([60, 130, 350, 175], fill="#3B82F6")
    draw.text((205, 152), "1. User Interface (UI/UX)", font=f_card_title, fill="#FFFFFF", anchor="mm")
    lines1 = [
        "• Desktop / Web UI (Streamlit)",
        "• Multi-Language: C++, C, Py, Java, JS",
        "• Pygments Red-Line Highlight",
        "• Custom Test Cases (stdin/stdout)"
    ]
    y = 195
    for l in lines1:
        draw.text((80, y), l, font=f_body, fill="#334155")
        y += 26

    # Arrow 1 -> 2
    draw_arrow(draw, (350, 225), (430, 225), fill="#2563EB", width=4)

    # Step 2: Security Validator Gate
    c2 = (430, 130, 770, 320)
    draw_rounded_card(draw, c2, fill="#FFFFFF", outline="#D97706", radius=12, width=2)
    draw.rectangle([430, 130, 770, 175], fill="#D97706")
    draw.text((600, 152), "2. Security Validator Engine", font=f_card_title, fill="#FFFFFF", anchor="mm")
    lines2 = [
        "• Heuristic Prompt Injection Defense",
        "• 9-Stage CWE Vulnerability Scanner",
        "• Flags buffer overflows: gets(), strcpy()",
        "• DLP: Masks student PII & leaked keys"
    ]
    y = 195
    for l in lines2:
        draw.text((450, y), l, font=f_body, fill="#334155")
        y += 26

    # Decision Diamond 1: Threat Detected?
    # Diamond at (900, 225)
    d1_pts = [(900, 165), (980, 225), (900, 285), (820, 225)]
    draw.polygon(d1_pts, fill="#FEF3C7", outline="#D97706")
    draw.text((900, 225), "Threat\nFound?", font=f_badge, fill="#92400E", anchor="mm", align="center")

    draw_arrow(draw, (770, 225), (820, 225), fill="#D97706", width=4)

    # Threat Branch: Up & Left to Security Alert Box
    draw_arrow(draw, (900, 165), (900, 110), fill="#DC2626", width=3)
    c_alert = (780, 30, 1020, 110)
    draw_rounded_card(draw, c_alert, fill="#FEF2F2", outline="#EF4444", radius=10, width=2)
    draw.text((900, 55), "Security Threat Blocked!", font=f_card_title, fill="#DC2626", anchor="mm")
    draw.text((900, 85), "Explains CWE flaw & gives safe API", font=f_badge, fill="#991B1B", anchor="mm")

    # Safe Branch (No Threat): Down into Step 3 Sandbox
    draw_arrow(draw, (900, 285), (900, 390), fill="#059669", width=4)
    draw.text((940, 335), "Safe (No Threat)", font=f_badge, fill="#059669")

    # Step 3: Dual Sandboxed Execution Subsystem
    c3 = (700, 390, 1100, 560)
    draw_rounded_card(draw, c3, fill="#FFFFFF", outline="#059669", radius=12, width=2)
    draw.rectangle([700, 390, 1100, 435], fill="#059669")
    draw.text((900, 412), "3. Dual Execution Sandbox", font=f_card_title, fill="#FFFFFF", anchor="mm")
    lines3 = [
        "• Primary: Docker Container (--network none, read-only)",
        "• Fallback: POSIX Subprocess (RLIMIT_CPU 5s cap)",
        "• Zero network leakage & dropped root privileges",
        "• Isolates infinite loops, segfaults, & crash signals"
    ]
    y = 450
    for l in lines3:
        draw.text((720, y), l, font=f_body, fill="#334155")
        y += 24

    # Decision Diamond 2: Error Found?
    d2_pts = [(550, 475), (620, 475), (550, 535), (480, 475)] # Below or to side
    # Let's place it at (550, 475)
    draw_arrow(draw, (700, 475), (610, 475), fill="#475569", width=4)

    d2_pts = [(550, 435), (610, 475), (550, 515), (490, 475)]
    draw.polygon(d2_pts, fill="#E2E8F0", outline="#475569")
    draw.text((550, 475), "Errors\nFound?", font=f_badge, fill="#0F172A", anchor="mm", align="center")

    # If No Errors: Success!
    draw_arrow(draw, (550, 435), (550, 370), fill="#059669", width=3)
    c_success = (460, 320, 640, 370)
    draw_rounded_card(draw, c_success, fill="#ECFDF5", outline="#10B981", radius=8, width=2)
    draw.text((550, 345), "Execution Success (0 Errors)", font=f_badge, fill="#065F46", anchor="mm")

    # If Errors Found: Down to Context Extractor
    draw_arrow(draw, (550, 515), (550, 630), fill="#DC2626", width=4)
    draw.text((580, 570), "Compile / Runtime Error", font=f_badge, fill="#DC2626")

    # Step 4: Error Context Extractor & Typo Engine
    c4 = (380, 630, 720, 810)
    draw_rounded_card(draw, c4, fill="#FFFFFF", outline="#6366F1", radius=12, width=2)
    draw.rectangle([380, 630, 720, 675], fill="#6366F1")
    draw.text((550, 652), "4. Context Extractor & Typo Engine", font=f_card_title, fill="#FFFFFF", anchor="mm")
    lines4 = [
        "• Multi-Language Regex (GCC/Clang, javac)",
        "• Python AST & Runtime Traceback Parser",
        "• RapidFuzz Levenshtein Typo Suggestions",
        "• Code Quality & Complexity Classifier"
    ]
    y = 695
    for l in lines4:
        draw.text((400, y), l, font=f_body, fill="#334155")
        y += 24

    # Arrow 4 -> 5
    draw_arrow(draw, (720, 720), (810, 720), fill="#6366F1", width=4)

    # Step 5: AI Repair Engine
    c5 = (810, 630, 1150, 810)
    draw_rounded_card(draw, c5, fill="#FFFFFF", outline="#8B5CF6", radius=12, width=2)
    draw.rectangle([810, 630, 1150, 675], fill="#8B5CF6")
    draw.text((980, 652), "5. ReAct Agent AI Engine", font=f_card_title, fill="#FFFFFF", anchor="mm")
    lines5 = [
        "• Dual AI: Local Llama 3 (Offline) or Gemini",
        "• Structured XML Hierarchical Prompts",
        "• 8-Turn ReAct (Thought -> Action -> Observe)",
        "• Generates Root Cause + Fix Candidate"
    ]
    y = 695
    for l in lines5:
        draw.text((830, y), l, font=f_body, fill="#334155")
        y += 24

    # Arrow 5 -> 6
    draw_arrow(draw, (1150, 720), (1230, 720), fill="#8B5CF6", width=4)

    # Step 6: Closed-Loop Sandbox Fix Verification
    c6 = (1230, 630, 1450, 810)
    draw_rounded_card(draw, c6, fill="#FFFFFF", outline="#059669", radius=12, width=2)
    draw.rectangle([1230, 630, 1450, 675], fill="#059669")
    draw.text((1340, 652), "6. Sandbox Verifier", font=f_card_title, fill="#FFFFFF", anchor="mm")
    lines6 = [
        "• Re-compiles fix",
        "• Runs test suite",
        "• Compares I/O diff",
        "• Re-checks security"
    ]
    y = 695
    for l in lines6:
        draw.text((1250, y), l, font=f_body, fill="#334155")
        y += 24

    # Feedback Loop if Fix Fails: from 6 back to 5
    draw.line([(1340, 810), (1340, 845), (980, 845)], fill="#DC2626", width=3)
    draw_arrow(draw, (980, 845), (980, 810), fill="#DC2626", width=3)
    draw.text((1150, 830), "Fix Failed (Self-Correction)", font=f_badge, fill="#DC2626", anchor="mm")

    # Step 7: Final Output to User
    c7 = (380, 910, 1150, 1080)
    draw_rounded_card(draw, c7, fill="#ECFDF5", outline="#10B981", radius=14, width=2)
    draw.rectangle([380, 910, 1150, 955], fill="#10B981")
    draw.text((765, 932), "7. Verified Output Presented to Student", font=f_card_title, fill="#FFFFFF", anchor="mm")
    lines7 = [
        "✓ Plain-English Root Cause Explanation & Pedagogical Hint (Encourages deeper understanding)",
        "✓ Side-by-Side Unified Code Diff (Green additions, red deletions with one-click 'Apply Fix')",
        "✓ Test Suite Pass Badges & Live CodeCarbon Green Telemetry (Watt-hours & kg CO2eq)"
    ]
    y = 975
    for l in lines7:
        draw.text((410, y), l, font=f_body, fill="#065F46")
        y += 26

    # Arrow from 6 down to 7
    draw.line([(1340, 630), (1340, 590), (1200, 590), (1200, 995)], fill="#10B981", width=3)
    draw_arrow(draw, (1200, 995), (1150, 995), fill="#10B981", width=3)
    draw.text((1240, 975), "Tests Passed!", font=f_badge, fill="#059669")

    # Arrow from 7 back to 1
    draw.line([(380, 995), (205, 995), (205, 320)], fill="#3B82F6", width=3)
    draw_arrow(draw, (205, 335), (205, 320), fill="#3B82F6", width=3)
    draw.text((220, 650), "Delivered to Student UI", font=f_badge, fill="#2563EB", rotation=90)

    img.save(out_path, "PNG", dpi=(300, 300))
    print(f"Proposed architecture diagram saved to {out_path}")

if __name__ == "__main__":
    out_dir = "/Users/arpit/toa_project/images"
    os.makedirs(out_dir, exist_ok=True)
    render_existing_architecture(f"{out_dir}/existing_architecture.png")
    render_proposed_architecture(f"{out_dir}/proposed_architecture.png")
