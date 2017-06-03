
import sys
from Tkinter import *
import socket
import nmap
from datetime import datetime
import urllib
from bs4 import BeautifulSoup
import urlparse

nm = nmap.PortScanner()


def hacer_click():
    global texto
    texto=str(entrada_texto.get())
    if texto:
        etiqueta.config(text=("Target:",texto))
        nueva_ventana()
    else:
        etiqueta.config(text="Introduce the target")

def DrawList(): # Se crea una lista con los equipos escaneados
        global hosts_list          
        nm.scan(hosts=texto, arguments='-n -sP -PE -PA21,23,80,3389')
        hosts_list = [(x, nm[x]['status']['state'])for x in nm.all_hosts()]
        elemento=0
        for host, status in hosts_list:
            elemento=elemento+1
            item=elemento,'-',str(host)
            listbox.insert(END,item)
def elem():#Escaneo de puertos
    global t_t
    a=listbox.curselection()
    
    host=int(a[0])
    host=hosts_list[host][0]
    t_in = datetime.now()
    nm.scan(host, '1-10000')

    #Una forma de escaneo de puertos
    """    for port in nm[ip]['tcp']:
        data = nm[ip]['tcp'][port]
        item='Port',str(port),data['product'],data['version']"""
    
    for host in nm.all_hosts():
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
             print('Protocol : %s' % proto)
             lport = nm[host][proto].keys()
             lport.sort()
             for port in lport:
                data = nm[host]['tcp'][port]
                item='Port:',port,'---State:',nm[host][proto][port]['state'],'---',data['product'],'---',data['version']
                listbox2.insert(END,item)
    t_fin = datetime.now()
    t_t = t_fin - t_in
    time='Scanned:',str(t_t.total_seconds()),'seconds'
    listbox2.insert (END,'\n')
    listbox2.insert (END,time)
        
def nueva_ventana():# Se crea la segunda ventana
    global listbox, listbox2
    window = Toplevel(app)
    window.title("List of Available Hosts")
    window.geometry("500x450")
    listbox=Listbox(window)
    listbox2=Listbox(window, width=60)
    boton = Button(window,text = "Show Hosts",command = DrawList,cursor="pointinghand",bitmap="hourglass", compound="left")
    boton2 = Button(window,text = "Scan port",command = elem,cursor="spinning",bitmap="hourglass", compound="left")
    boton.pack()
    listbox.pack()
    boton2.pack()
    listbox2.pack()
    window.mainloop()
    
def informacion():# Se crea una ventana de informacion
    window = Toplevel(app)
    window.title("About")
    window.geometry("350x100")
    etiqueta = Label(window, text="Port Scanner V1.0 \n  Port Scanner is a free utility for network discovery... \n\n Developed by:\n Emilio Revelo\n ")
    etiqueta.pack()
    window.mainloop()   

def crawler():# Se crea ventana donde se listaran los elementos arrojados del crawler
    global url
    url=str(entrada_texto2.get())
    if url:
        urls = [url]
        visited = [url]       
        window = Toplevel(app)
        window.title("List of URL's")
        window.geometry("600x530")
        listb=Listbox(window, width=60, height=30)
        while len(urls)>0:
            ht=urllib.urlopen(urls[0]).read()       
            soup=BeautifulSoup(ht)
            urls.pop(0)
            for tag in soup.findAll('a',href=True):
                tag['href']=urlparse.urljoin(url,tag['href'])
                res=tag['href']
                listb.insert (END,res)
        listb.pack()
        window.mainloop()
    else:
        etiqueta6.config(text="Introduce the URL")

#Caracteristicas de la ventana 
app = Tk()
app.title("Port Scanner v1.0")
app.geometry("355x220")
#img = PhotoImage(
#widget = Label(app, image=img).place(x=10,y=10)

#Ventana Principal
etiqueta = Label(app, text="Network")
etiqueta2 = Label(app, text="Port Scanner")
etiqueta3 = Label(app, text="----------------------------------------------------")
etiqueta4 = Label(app, text="Crawler")
etiqueta5 = Label(app, text="URL:").place(x=1,y=145)
etiqueta6 = Label(app, text="")
boton = Button(app, text="Start", command=hacer_click,cursor="pointinghand", bitmap="hourglass", compound="left")
boton2 = Button(app, text="Start", command=crawler,cursor="pointinghand", bitmap="questhead", compound="left")
valor = ""
entrada_texto = Entry(app, width=18, textvariable=valor, justify="center")
entrada_texto2 = Entry(app, width=30, textvariable=valor, justify="center")
info=Button(app,command=informacion,cursor="pointinghand", bitmap="warning").place(x=340,y=193)
etiqueta2.pack()
entrada_texto.pack()
boton.pack()
etiqueta.pack()
etiqueta3.pack()
etiqueta4.pack()
entrada_texto2.pack()
boton2.pack()
etiqueta6.pack()
app.mainloop()
