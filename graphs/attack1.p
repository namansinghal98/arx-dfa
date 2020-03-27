#!/usr/bin/gnuplot
reset

# png
set terminal pngcairo size 600,400 enhanced font 'Verdana,9'
set output 'attack1.png'

# set border linewidth 1.5
# Set first two line styles to blue (#0060ad) and red (#dd181f)
set style line 1 \
    linecolor rgb '#0060ad' \
    linetype 1 linewidth 1 \
    pointtype 7 pointsize 1.2
set style line 2 \
    linecolor rgb '#dd181f' \
    linetype 1 linewidth 1 \
    pointtype 7 pointsize 1.2
set style line 3 \
    linecolor rgb '#DAA520' \
    linetype 1 linewidth 1 \
    pointtype 7 pointsize 1.2
set style line 4 \
    linecolor rgb '#228B22' \
    linetype 1 linewidth 1 \
    pointtype 7 pointsize 1.2
set style line 5 \
    linecolor rgb '#8B008B' \
    linetype 1 linewidth 1 \
    pointtype 7 pointsize 1.2

set style line 6 \
    linecolor rgb '#0060ad' \
    linetype 6 linewidth 0.4 \
    pointtype 4 pointsize 1
set style line 7 \
    linecolor rgb '#dd181f' \
    linetype 7 linewidth 0.4 \
    pointtype 4 pointsize 1
set style line 8 \
    linecolor rgb '#DAA520' \
    linetype 8 linewidth 0.4 \
    pointtype 4 pointsize 1
set style line 9 \
    linecolor rgb '#228B22' \
    linetype 9 linewidth 0.4 \
    pointtype 4 pointsize 1
set style line 10 \
    linecolor rgb '#8B008B' \
    linetype 10 linewidth 0.4 \
    pointtype 4 pointsize 1


#unset key
set title "Fault Attack Results on SIMON N=16,24,32"
set key right top
set xlabel 'Fault Round'
set ylabel '# Faults'
set y2label 'Success %'
set ytics nomirror
set y2tics 10

set grid 
set yrange [0:16]
set y2range [0:100]
set autoscale y
set autoscale y2

#set origin 0,0
plot 'attack1faults.dat' using 2:xticlabels(1) with linespoints linestyle 1 notitle axis x1y1, \
     ''               using 3:xticlabels(1) with linespoints linestyle 2 notitle axis x1y1, \
     ''               using 4:xticlabels(1) with linespoints linestyle 3 notitle axis x1y1, \
     ''               using 5:xticlabels(1) with linespoints linestyle 4 notitle axis x1y1, \
     ''               using 6:xticlabels(1) with linespoints linestyle 5 notitle axis x1y1, \
     'attack1succ.dat'   using 2:xticlabels(1) with linespoints linestyle 6 notitle axis x1y2, \
    ''              using 3:xticlabels(1) with linespoints linestyle 7 notitle axis x1y2, \
     ''              using 4:xticlabels(1) with linespoints linestyle 8 notitle axis x1y2, \
     ''              using 5:xticlabels(1) with linespoints linestyle 9 notitle axis x1y2, \
     ''              using 6:xticlabels(1) with linespoints linestyle 10 notitle axis x1y2, \
     "+"  u 1:(NaN)  with line lc rgb '#0060ad' title 'SIMON(32/64)', \
     "+"  u 1:(NaN)  with line lc rgb '#dd181f' title 'SIMON(48/72)', \
     "+"  u 1:(NaN)  with line lc rgb '#DAA520' title 'SIMON(48/96)', \
     "+"  u 1:(NaN)  with line lc rgb '#228B22' title 'SIMON(64/96)', \
     "+"  u 1:(NaN)  with line lc rgb '#8B008B' title 'SIMON(64/64)', \
     "+"  u 1:(NaN)  w dots lc rgb "white" t " ", \
     "+"  u 1:(NaN)  with linespoints pointtype 7 ps 1 lc rgb 'black' title "Faults", \
     "+"  u 1:(NaN)  with linespoints pointtype 4 ps 1 lc rgb 'black' title "Success"

