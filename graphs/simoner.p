#!/usr/bin/gnuplot
#

reset

# png
set terminal pngcairo size 600,400 enhanced font 'Verdana,9'
set output 'simoner.png'

set border linewidth 1.5
# Set first two line styles to blue (#0060ad) and red (#dd181f)
set style line 1 \
    linecolor rgb '#0060ad' \
    linetype 1 linewidth 0.4 \
    pointtype 7 pointsize 1.0
set style line 2 \
    linecolor rgb '#dd181f' \
    linetype 1 linewidth 0.4 \
    pointtype 7 pointsize 1.0
set style line 3 \
    linecolor rgb '#DAA520' \
    linetype 1 linewidth 0.4 \
    pointtype 7 pointsize 1.0
set style line 4 \
    linecolor rgb '#228B22' \
    linetype 1 linewidth 0.4 \
    pointtype 7 pointsize 1.0
set style line 5 \
    linecolor rgb '#8B008B' \
    linetype 1 linewidth 0.4 \
    pointtype 7 pointsize 1.0

#unset key
set title "{/Symbol D} H_{total} for 1-bit fault in SIMON"
set key right top
set xlabel 'Round'
set ylabel '{/Symbol D} H_{total}' enhanced

set grid 
set yrange [0:16]
set autoscale y

#set origin 0,0
plot 'simoner.dat' using 2:xticlabels(1) with linespoints linestyle 1 t 'SIMON(32/16M)', \
     ''              using 3:xticlabels(1) with linespoints linestyle 2 t 'SIMON(48/24M)', \
     ''              using 4:xticlabels(1) with linespoints linestyle 3 t 'SIMON(64/32M)', \
     ''              using 5:xticlabels(1) with linespoints linestyle 4 t 'SIMON(96/48M)', \
     ''              using 6:xticlabels(1) with linespoints linestyle 5 t 'SIMON(128/64M)' \
