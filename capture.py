from scapy.all import sniff, TCP
from scapy.layers.inet import IP

# Definir el filtro de captura para el puerto 502 de Modbus
def filtro_modbus(packet):
    return TCP in packet and (packet[TCP].sport == 502 or packet[TCP].dport == 502)

# Función para manejar cada paquete capturado
def manejar_paquete(packet):
    # Asumiendo que es un paquete Modbus/TCP, puedes extraer campos específicos aquí
    print(f"Paquete capturado de {packet[IP].src} a {packet[IP].dst}")
    if len(packet[TCP].payload):
        datos = packet[TCP].payload.load
        print("Datos del paquete (puede incluir cabecera Modbus):", datos)

# Iniciar la captura
print("Iniciando la captura de paquetes Modbus en el puerto 502...")
sniff(prn=manejar_paquete, lfilter=filtro_modbus, iface="ens36", store=False)
