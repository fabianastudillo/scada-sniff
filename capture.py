from scapy.all import sniff, TCP
from scapy.layers.inet import IP
import scapy.contrib.modbus as mb
import logging
from gelfformatter import GelfFormatter
from graypy import GELFUDPHandler

# Definir el filtro de captura para el puerto 502 de Modbus
def filtro_modbus(packet):
    return TCP in packet and (packet[TCP].sport == 502 or packet[TCP].dport == 502)

# Función para manejar cada paquete capturado
def manejar_paquete(packet):
    # Asumiendo que es un paquete Modbus/TCP, puedes extraer campos específicos aquí
    print(f"Paquete capturado de {packet[IP].src} a {packet[IP].dst}")
    #if len(packet[TCP].payload):
    #    datos = packet[TCP].payload.load
    #    print("Datos del paquete (puede incluir cabecera Modbus):", datos)
    if mb.ModbusADUResponse in packet:
        logger.debug("ADUResponse IP.src={packet[IP].src} IP.dst={packet[IP].dst}")
        #packet.show()
    elif mb.ModbusADURequest in packet:
        logger.debug("ADURequest IP.src={packet[IP].src} IP.dst={packet[IP].dst}")
        #packet.show()

# Set logs
logger = logging.getLogger("gelf")
logger.setLevel(logging.DEBUG)

handler = GELFUDPHandler(host="127.0.0.1", port=5514)
handler.setFormatter(GELFFormatter(null_character=True))
logger.addHandler(handler)
# Iniciar la captura
print("Iniciando la captura de paquetes Modbus en el puerto 502...")
sniff(prn=manejar_paquete, lfilter=filtro_modbus, iface="ens36", store=False)
