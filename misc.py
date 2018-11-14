# Copyright (C) 2016   Manmeet Singh, Maninder Singh, Sanmeet kour
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
#

# !python2

# Misc functions

#Edit distance
import numpy as np
from sklearn.metrics import jaccard_similarity_score
import scipy

def LD(s, t):
    print (s,t)
    if s == "":
        return len(t)
    if t == "":
        return len(s)
    if s[-1] == t[-1]:
        cost = 0
    else:
        cost = 1

    res = min([LD(s[:-1], t) + 1,
               LD(s, t[:-1]) + 1,
               LD(s[:-1], t[:-1]) + cost])
    return res

def edit_distance():
    s="Pythooooon"
    t= "Pytho"
    print(s[:-1])

    print(LD(s,t ))

#Jaccard Index
def jaccard():
    y_pred = [0, 2, 1, 3]
    y_true = [0, 1, 2, 3]
    print(jaccard_similarity_score(y_true, y_pred))
    print(jaccard_similarity_score(y_true, y_pred, normalize=False))

def entropy():
    t1 = scipy.stats.norm(-2.5, 0.1)
    t2 = scipy.stats.norm(-2.5, 0.1)
    t3 = scipy.stats.norm(-2.4, 0.1)
    t4 = scipy.stats.norm(-2.3, 0.1)

    # domain to evaluate PDF on

    x = np.linspace(-5, 5, 100)

    print(scipy.stats.entropy(t1.pdf(x), t2.pdf(x)))
    print(scipy.stats.entropy(t1.pdf(x), t3.pdf(x)))
    print(scipy.stats.entropy(t1.pdf(x), t4.pdf(x)))


import numpy as np
import pandas as pd
size = 1000
data = [['Gamma' , np.random.gamma(1., 2., size)],
['Normal', np.random.normal(0, 2., size)],
['Exponential', np.random.exponential(0.9, size)]]

def countNumberFromCStdOfMean(values, c):
    std = np.std(values)
    mean = np.mean(values)
    return np.sum(np.absolute(values - mean) >= c * std)

#c = 4.46
#results = [[ d[0] , np.mean(d[1]), np.std(d[1]), countNumberFromCStdOfMean(d[1], c)] for d in data]

#df = pd.DataFrame(data = results)
#df.columns = ['Distribution', 'Mean', 'Std', 'Number c stds from mean']
#print(df)




import numpy as np
import matplotlib.pyplot as plt

def f(t):
    return np.exp(-t) * np.cos(2*np.pi*t)

t1 = np.arange(0.0, 5.0, 0.1)
t2 = np.arange(0.0, 5.0, 0.02)

plt.figure(1)
plt.subplot(211)
plt.plot(t1, f(t1), 'bo', t2, f(t2), 'k')

plt.subplot(212)
plt.plot(t2, np.cos(2*np.pi*t2), 'r--')
plt.show()
