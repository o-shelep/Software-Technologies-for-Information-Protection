import os
import sys

# Дозволяє запускати pytest з кореня проєкту без встановлення пакета.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
