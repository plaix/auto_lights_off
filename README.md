I needed a passive way for my Philips Hue lights to know when I left the house in case I forgot to turn them off.

I settled on passively monitoring my phone on the network, so this is quickly thrown together and based on IOS devices.

USAGE

pip install -r requirements.txt

python app.py -m MAC -b IP 
-d / for debug

TODO

Make it into a daemon
