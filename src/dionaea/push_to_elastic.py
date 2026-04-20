import pandas as pd
from src.common.elastic import push_to_elastic

df = pd.read_csv("data/dionaea/predictions/predictions.csv")

push_to_elastic(df, "malware-detection")