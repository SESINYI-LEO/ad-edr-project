"""Charts for Chapter 4 from results/*.csv|json."""
import csv, json, sys
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
OUT = sys.argv[1] if len(sys.argv) > 1 else "results"
INK="#1f2937"; MUTED="#6b7280"; GRID="#e5e7eb"; BLUE="#2f5fcf"; GREY="#8a94a6"
plt.rcParams.update({"font.family":"DejaVu Serif","font.size":9,"text.color":INK,"axes.labelcolor":INK,"xtick.color":INK,"ytick.color":INK})
rows=list(csv.DictReader(open("results/scenario_results.csv")))
fig,ax=plt.subplots(figsize=(7.4,3.4),dpi=200)
for i,r in enumerate(rows):
    v=float(r["ingest_rtt_ms"]); atk=r["kind"]=="attack"
    ax.bar(i,v,width=0.62,color=BLUE if atk else "white",edgecolor=BLUE if atk else GREY,linewidth=1.0,hatch=None if atk else "////",zorder=3)
ax.set_xticks(range(len(rows))); ax.set_xticklabels([r["id"] for r in rows],rotation=90,fontsize=7.5)
ax.set_ylabel("Ingest-to-alert round trip (ms)"); ax.yaxis.grid(True,color=GRID,zorder=0); ax.set_axisbelow(True)
for s in ("top","right"): ax.spines[s].set_visible(False)
ax.spines["left"].set_color(GRID); ax.spines["bottom"].set_color(MUTED)
mx=max(float(r["ingest_rtt_ms"]) for r in rows); first=float(rows[0]["ingest_rtt_ms"])
if first==mx and first>100:
    ax.annotate(f"first request of the run ({first:.0f} ms)",xy=(0,first),xytext=(3,first*0.82),fontsize=8,color=MUTED,arrowprops=dict(arrowstyle="-",color=MUTED,lw=0.8))
ax.set_ylim(0,mx*1.12)
ax.legend(handles=[Patch(facecolor=BLUE,edgecolor=BLUE,label="Attack scenario (alert raised)"),Patch(facecolor="white",edgecolor=GREY,hatch="////",label="Benign look-alike (no alert)")],frameon=False,loc="upper right",fontsize=8)
fig.tight_layout(); fig.savefig(f"{OUT}/chart_latency.png"); plt.close(fig)
cov=json.load(open("results/coverage.json"))["files"]; data=[]
for f,d in cov.items():
    s=d["summary"]
    if s["num_statements"]==0: continue
    tot=s["num_statements"]+s["num_branches"]; cv=s["covered_lines"]+s["covered_branches"]
    data.append((f.replace("server/app/","server/").replace("agent/edr_agent/","agent/"),100*cv/tot))
data.sort(key=lambda x:x[1])
fig,ax=plt.subplots(figsize=(7.4,5.6),dpi=200)
for i,(n,p) in enumerate(data):
    ax.barh(i,p,height=0.6,color=BLUE,zorder=3); ax.text(p+1,i,f"{p:.0f}%",va="center",fontsize=8)
ax.set_yticks(range(len(data))); ax.set_yticklabels([d[0] for d in data],fontsize=8)
ax.set_xlim(0,112); ax.set_xlabel("Combined statement and branch coverage (%)"); ax.xaxis.grid(True,color=GRID,zorder=0)
for s in ("top","right"): ax.spines[s].set_visible(False)
ax.spines["left"].set_color(MUTED); ax.spines["bottom"].set_color(GRID)
fig.tight_layout(); fig.savefig(f"{OUT}/chart_coverage.png"); plt.close(fig)
