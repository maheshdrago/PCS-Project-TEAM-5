import pandas as pd
import pickle
import pefile
import joblib

malData=pd.read_csv("MalwareData.csv", sep="|")
legit=malData[0:41323].drop(["legitimate"],axis=1)
mal=malData[41323::].drop(["legitimate"],axis=1)
print("the shape of the legit dataset is : %s samples , %s features"%(legit.shape[0], legit.shape[1]))
print("the shape of the malware dataset is : %s samples , %s features"%(mal.shape[0], mal.shape[1]))
print(malData.columns)
print(malData.head(5))
pd.set_option("display.max_columns", None)
print(malData.head(5))
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.model_selection import train_test_split
#from sklearn import cross_validation
data_in=malData.drop(['Name', 'md5', 'legitimate'], axis=1).values
labels=malData['legitimate'].values
extratrees=ExtraTreesClassifier().fit(data_in, labels)
select=SelectFromModel(extratrees, prefit=True)
data_in_new=select.transform(data_in)
print(data_in.shape, data_in_new.shape)
import numpy as np 
features =data_in_new.shape[1]
importances=extratrees.feature_importances_
indices=np.argsort(importances)[::-1]
newfeatures=[]

for f in range(features):
    print("%d"%(f+1), malData.columns[2+indices[f]],importances[indices[f]])
    newfeatures.append(malData.columns[2+f])


from sklearn.ensemble import RandomForestClassifier
legit_train , legit_test, mal_train , mal_test= train_test_split(data_in_new, labels, test_size=0.3)
classif= RandomForestClassifier(n_estimators=50)
algoclassifier=classif.fit(legit_train, mal_train)
print("the score of the algorithm :", classif.score(legit_test , mal_test)*100)

print('Saving algorithm and feature list in classifier directory...')
joblib.dump(algoclassifier, 'classifier/classifier.pkl')
open('classifier/features.pkl', 'wb').write(pickle.dumps(newfeatures))





from sklearn.metrics import confusion_matrix
result=classif.predict(data_in_new)
#result= classif. predict(legit_test)
conf_mat=confusion_matrix(labels,result)
#conf_mat= confusion_matrix(mal_test , result)

conf_mat.shape
type(conf_mat)
conf_mat
print("false positives: ", conf_mat[0][1]/sum(conf_mat[0])*100)
print("False negatives" , conf_mat[1][0]/sum(conf_mat[1])*100)

# from sklearn.ensemble import GradientBoostingClassifier
# grad_boost= GradientBoostingClassifier(n_estimators=50)
# grad_boost.fit(legit_train, mal_train)


# print("The score of the Gradient boosting Classifier is: " , grad_boost.score(legit_test, mal_test)* 100)
