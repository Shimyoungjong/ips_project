#!/usr/bin/env python3
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import matplotlib.font_manager as fm
import os

# Find Korean font on macOS
def find_korean_font():
    candidates = [
        '/System/Library/Fonts/AppleSDGothicNeo.ttc',
        '/System/Library/Fonts/Supplemental/AppleGothic.ttf',
        '/Library/Fonts/NanumGothic.ttf',
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    for f in fm.fontManager.ttflist:
        if any(k in f.name for k in ['Gothic', 'Nanum', 'Apple SD', 'Malgun']):
            return f.fname
    return None

font_path = find_korean_font()
print(f"Using font: {font_path}")

def fp(size=10, bold=False):
    w = 'bold' if bold else 'normal'
    if font_path:
        return fm.FontProperties(fname=font_path, size=size, weight=w)
    return fm.FontProperties(size=size, weight=w)

fig, axes = plt.subplots(1, 2, figsize=(16, 10), gridspec_kw={'width_ratios': [1.1, 0.9]})
fig.patch.set_facecolor('#F0F4F8')

ax = axes[0]
ax.set_xlim(0, 11)
ax.set_ylim(0, 10)
ax.axis('off')
ax.set_facecolor('#F0F4F8')

ax2 = axes[1]
ax2.set_xlim(0, 8)
ax2.set_ylim(0, 10)
ax2.axis('off')
ax2.set_facecolor('#F0F4F8')

def draw_diamond(ax, cx, cy, w, h, fc, ec, text, fsize=9.5, bold=False):
    pts = [[cx, cy+h/2], [cx+w/2, cy], [cx, cy-h/2], [cx-w/2, cy]]
    poly = plt.Polygon(pts, closed=True, facecolor=fc, edgecolor=ec, linewidth=2.2, zorder=3)
    ax.add_patch(poly)
    ax.text(cx, cy, text, ha='center', va='center', fontproperties=fp(fsize, bold),
            color='white', zorder=4)

def draw_box(ax, cx, cy, w, h, fc, ec, text, fsize=10, bold=False):
    rect = FancyBboxPatch((cx-w/2, cy-h/2), w, h,
                          boxstyle="round,pad=0.08", facecolor=fc,
                          edgecolor=ec, linewidth=2, zorder=3)
    ax.add_patch(rect)
    ax.text(cx, cy, text, ha='center', va='center', fontproperties=fp(fsize, bold),
            color='white', zorder=4)

def draw_arrow(ax, x1, y1, x2, y2, label='', lcolor='#555555'):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle='->', color=lcolor, lw=2.0), zorder=2)
    if label:
        is_horizontal = abs(y2 - y1) < abs(x2 - x1)
        mx = (x1+x2)/2
        my = (y1+y2)/2
        if is_horizontal:
            my += 0.22  # 수평 화살표는 레이블을 위로
        else:
            mx += 0.25  # 수직 화살표는 레이블을 오른쪽으로
        ax.text(mx, my, label, fontproperties=fp(9, True), color=lcolor, zorder=5)

# ===== LEFT: Decision Tree =====
ax.text(5, 9.55, '의사결정 트리 (단일 트리 예시)', ha='center',
        fontproperties=fp(14, True), color='#1A1A2E', zorder=5)
ax.text(5, 9.18, '65개 플로우 피처  ->  공격 유형 분류', ha='center',
        fontproperties=fp(10), color='#555', zorder=5)

# Root
draw_box(ax, 5, 8.55, 4.2, 0.72, '#2E4057', '#1A2840',
         '65개 플로우 피처 (입력)', 10.5, True)
draw_arrow(ax, 5, 8.19, 5, 7.78)

# Node 1
draw_diamond(ax, 5, 7.32, 4.6, 0.85, '#E76F51', '#C85A3C',
             'flow_pkts_s > 1000 ?', 9.5, True)
draw_arrow(ax, 7.3, 7.32, 8.35, 7.32, 'YES')
draw_box(ax, 9.08, 7.32, 1.35, 0.58, '#D62828', '#B22020', 'DDoS', 9.5, True)
draw_arrow(ax, 5, 6.89, 5, 6.42, 'NO')

# Node 2
draw_diamond(ax, 5, 5.98, 4.4, 0.85, '#E76F51', '#C85A3C',
             'syn_ratio > 0.9 ?', 9.5, True)
draw_arrow(ax, 7.2, 5.98, 8.35, 5.98, 'YES')
draw_box(ax, 9.15, 5.98, 1.7, 0.58, '#D62828', '#B22020', 'SYN Flood', 9, True)
draw_arrow(ax, 5, 5.55, 5, 5.08, 'NO')

# Node 3
draw_diamond(ax, 5, 4.62, 4.8, 0.85, '#E76F51', '#C85A3C',
             'dst_port 다양성 > 30 ?', 9.5, True)
draw_arrow(ax, 7.4, 4.62, 8.35, 4.62, 'YES')
draw_box(ax, 9.2, 4.62, 1.8, 0.58, '#F4A261', '#D4823E', 'PortScan', 9, True)
draw_arrow(ax, 5, 4.19, 5, 3.72, 'NO')

# Node 4
draw_diamond(ax, 5, 3.28, 4.6, 0.85, '#E76F51', '#C85A3C',
             'payload_ratio > 0.8 ?', 9.5, True)
draw_arrow(ax, 7.3, 3.28, 8.35, 3.28, 'YES')
draw_box(ax, 9.2, 3.28, 1.8, 0.58, '#457B9D', '#2C5F7A', 'SQLi / XSS', 9, True)
draw_arrow(ax, 5, 2.85, 5, 2.38, 'NO')

# BENIGN
draw_box(ax, 5, 1.95, 2.8, 0.72, '#2A9D8F', '#1E7A6E', '정상 (BENIGN)', 10.5, True)

# Legend
ax.text(0.7, 1.1, '판단 노드', ha='center', fontproperties=fp(8.5, True), color='#E76F51')
ax.add_patch(plt.Polygon([[0.7,0.72],[1.1,0.55],[0.7,0.38],[0.3,0.55]],
                          closed=True, facecolor='#E76F51', edgecolor='none', alpha=0.8, zorder=2))
ax.text(2.3, 1.1, '결과 노드', ha='center', fontproperties=fp(8.5, True), color='#2A9D8F')
ax2_r = FancyBboxPatch((1.8, 0.4), 1.0, 0.35, boxstyle="round,pad=0.05",
                         facecolor='#2A9D8F', edgecolor='none', alpha=0.8, zorder=2)
ax.add_patch(ax2_r)

# ===== RIGHT: Ensemble =====
ax2.text(4, 9.55, 'Random Forest 앙상블', ha='center',
         fontproperties=fp(14, True), color='#1A1A2E', zorder=5)
ax2.text(4, 9.18, 'n_estimators=100 | 다수결 투표', ha='center',
         fontproperties=fp(10), color='#555', zorder=5)

ens_rect = FancyBboxPatch((0.4, 8.3), 7.2, 0.6,
                           boxstyle="round,pad=0.1", facecolor='#264653',
                           edgecolor='none', zorder=3)
ax2.add_patch(ens_rect)
ax2.text(4, 8.6, '100개 결정 트리  ->  다수결 투표  ->  최종 레이블',
         ha='center', va='center', fontproperties=fp(9.5, True), color='white', zorder=4)

categories = [
    ('DDoS',       1.00, '#D62828'),
    ('SYN Flood',  1.00, '#D62828'),
    ('PortScan',   1.00, '#F4A261'),
    ('BruteForce', 0.99, '#E9C46A'),
    ('SQLi',       0.95, '#457B9D'),
    ('XSS',        0.95, '#457B9D'),
    ('BENIGN',     0.97, '#2A9D8F'),
]

ax2.text(1.2, 7.85, '카테고리', ha='center', fontproperties=fp(9.5, True), color='#333')
ax2.text(5.0, 7.85, 'F1 스코어', ha='center', fontproperties=fp(9.5, True), color='#333')
ax2.plot([0.3, 7.7], [7.65, 7.65], color='#ccc', linewidth=1, zorder=2)

for i, (label, score, color) in enumerate(categories):
    y = 7.2 - i * 0.82
    ax2.text(1.2, y, label, ha='center', va='center',
             fontproperties=fp(10, True), color='#222', zorder=5)
    bar_w = score * 4.5
    rect_b = FancyBboxPatch((2.6, y-0.22), bar_w, 0.44,
                             boxstyle="round,pad=0.03", facecolor=color,
                             edgecolor='none', alpha=0.88, zorder=3)
    ax2.add_patch(rect_b)
    ax2.text(2.6 + bar_w + 0.12, y, f'{score:.2f}', ha='left', va='center',
             fontproperties=fp(9.5, True), color='#333', zorder=5)

summ_rect = FancyBboxPatch((0.4, 0.4), 7.2, 0.88,
                            boxstyle="round,pad=0.1", facecolor='#264653',
                            edgecolor='none', zorder=3)
ax2.add_patch(summ_rect)
ax2.text(4, 0.92, 'Macro Avg F1 = 0.98  |  정확도 98%',
         ha='center', va='center', fontproperties=fp(10.5, True), color='white', zorder=4)
ax2.text(4, 0.56, '학습 데이터 408,000개 플로우 (6개 클래스)  |  추론 < 2ms',
         ha='center', va='center', fontproperties=fp(9.5), color='#B0C4D8', zorder=4)

plt.tight_layout(pad=1.2)
_IPS_HOME = os.environ.get("IPS_HOME") or os.path.expanduser("~/ips_project")
out = os.path.join(_IPS_HOME, "rf_decision_tree.png")
plt.savefig(out, dpi=160, bbox_inches='tight', facecolor='#F0F4F8')
print(f"Saved: {out}")
plt.close()
