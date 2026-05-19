import pandas as pd

phiusiil = pd.read_csv('datasets/phiusiil.csv')
print(f'PhiUSIIL shape: {phiusiil.shape}')
print(phiusiil['label'].value_counts())

# iscx = pd.read_csv('datasets/iscx2016.csv')
# print(f'ISCX shape: {iscx.shape}')
# print(iscx['Type'].value_counts())

iscx = pd.read_csv('datasets/All.csv')
print(f'ISCX shape: {iscx.shape}')
print(iscx['URL_Type_obf_Type'].value_counts())
