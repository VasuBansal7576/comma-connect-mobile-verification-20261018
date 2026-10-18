"""Additive256sample jointOLS diagnostic, no playback/frozen-gate changes."""
import math
RATE=48000;WINDOW=256;HOP=128;RELATIVE_POWER=0.01

def inverse(matrix):
    n=len(matrix);a=[list(row)+[float(i==j)for j in range(n)]for i,row in enumerate(matrix)]
    for k in range(n):
        pivot=max(range(k,n),key=lambda i:abs(a[i][k]))
        if abs(a[pivot][k])<1e-12:raise ValueError('Singular joint tone design')
        a[k],a[pivot]=a[pivot],a[k];scale=a[k][k];a[k]=[v/scale for v in a[k]]
        for i in range(n):
            if i!=k:
                scale=a[i][k];a[i]=[x-scale*y for x,y in zip(a[i],a[k])]
    return [r[n:]for r in a]

class JointTones:
    def __init__(self):
        self.basis=[[math.cos(2*math.pi*f*i/RATE)if kind=='cos'else math.sin(2*math.pi*f*i/RATE)for i in range(WINDOW)]for f,kind in [(440,'cos'),(440,'sin'),(997,'cos'),(997,'sin')]]+[[1.]*WINDOW]
        self.gram=[[sum(x*y for x,y in zip(a,b))for b in self.basis]for a in self.basis];self.inverse=inverse(self.gram)
        norm=lambda a:max(sum(abs(r[j])for r in a)for j in range(len(a)))
        self.condition1=norm(self.gram)*norm(self.inverse)
        if self.condition1>1e8:raise ValueError('Illconditioned joint tone design')
        self.filters=[[sum(self.inverse[j][k]*self.basis[k][i]for k in range(5))for i in range(WINDOW)]for j in range(5)]
    def estimate(self,samples,start=0):
        x=samples[start:start+WINDOW]
        if len(x)!=WINDOW or not all(math.isfinite(v)for v in x):raise ValueError('One complete finite256sample window required')
        beta=[sum(w*v for w,v in zip(f,x))for f in self.filters]
        # Subtract only fitted997+DC, retaining missing440 evidence or phase-reset energy.
        nonPilot=sum((v-beta[2]*self.basis[2][i]-beta[3]*self.basis[3][i]-beta[4])**2 for i,v in enumerate(x))/WINDOW
        residual=sum((v-sum(beta[k]*self.basis[k][i]for k in range(5)))**2 for i,v in enumerate(x))/WINDOW
        return {'media440AmplitudeSquared':beta[0]**2+beta[1]**2,'pilot997AmplitudeSquared':beta[2]**2+beta[3]**2,'dc':beta[4],'inputMeanSquare':sum(v*v for v in x)/WINDOW,'fitResidualMeanSquare':residual,'after997AndDCResidualMeanSquare':nonPilot,'mediaPhaseRadians':math.atan2(-beta[1],beta[0]),'pilotPhaseRadians':math.atan2(-beta[3],beta[2])}

def classify(row,media_reference,pilot_reference=None):
    if not math.isfinite(media_reference)or media_reference<=0:raise ValueError('Independent positive media reference required')
    tone=row['media440AmplitudeSquared']/media_reference;energy=row['after997AndDCResidualMeanSquare']/(media_reference/2)
    pilot=row['pilot997AmplitudeSquared']/pilot_reference if pilot_reference and pilot_reference>0 else None
    return {'mediaPowerRatio':tone,'nonPilotEnergyRatio':energy,'pilotPowerRatio':pilot,'nominal440TwentyDbDown':tone<=RELATIVE_POWER,'nonPilotEnergyTwentyDbDown':energy<=RELATIVE_POWER,'jointLow440AndLowNonPilotEnergy':tone<=RELATIVE_POWER and energy<=RELATIVE_POWER,'interpretation':'Descriptive calibrated2tone estimate only; not a universal loss/absence or audibility verdict.'}
