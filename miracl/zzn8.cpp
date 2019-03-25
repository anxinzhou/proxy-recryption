/*
 *    MIRACL  C++ Implementation file zzn8.cpp
 *
 *    AUTHOR  : M. Scott
 *  
 *    PURPOSE : Implementation of class ZZn8  (Arithmetic over n^8)
 *
 * WARNING: This class has been cobbled together for a specific use with
 * the MIRACL library. It is not complete, and may not work in other 
 * applications
 *
 *    Note: This code assumes that -2 is a Quadratic Non-Residue,
 *          so modulus p=5 mod 8
 *
 *    Copyright (c) 2004 Shamus Software Ltd.
 */

#include "zzn8.h"

using namespace std;

ZZn8& ZZn8::powq(const ZZn4& w)
{ // Fr is "Frobenius root"
    ZZn4 t=w*w;   // square it to get Frobenius constant for ZZn4
    ZZn2 Fr;

    t.get(Fr);
    a.powq(Fr);
    b.powq(Fr);

    b*=w;

    return *this;
}

void ZZn8::get(ZZn4& x,ZZn4& y)  
{x=a; y=b;} 

void ZZn8::get(ZZn4& x) 
{x=a; }

ZZn8& ZZn8::operator*=(const ZZn8& x)
{ // optimized to reduce constructor/destructor calls
 if (&x==this)
 {
    ZZn4 t=a;
    t+=b;
    a*=a; 
    b*=b;
    t*=t;
    t-=a;
    t-=b; 
    a+=tx(b);
    b=t;

/* Colm O'hEigeartaigh spotted this possible improvement - thanks Colm

    ZZn4 t=a; t+=b;
    ZZn4 t2=a; t2+=tx(b);
    t*=t2;
    b*=a;
    t-=b;
    t-=tx(b);
    b+=b;
    a=t;
*/

 }
 else
 {
    ZZn4 ac=a; ac*=x.a;
    ZZn4 bd=b; bd*=x.b;
    ZZn4 t=x.a; t+=x.b;
    b+=a; b*=t; b-=ac; b-=bd;
    a=ac; a+=tx(bd);
 }
 return *this;
}

ZZn8& ZZn8::operator/=(const ZZn4& x)
{
    *this*=inverse(x);
    return *this;
}

ZZn8& ZZn8::operator/=(const ZZn& x)
{
    ZZn t=(ZZn)1/x;
    a*=t;
    b*=t;
    return *this;
}

ZZn8& ZZn8::operator/=(int i)
{
    ZZn t=(ZZn)1/i;
    a*=t;
    b*=t;
    return *this;
}

ZZn8& ZZn8::operator/=(const ZZn8& x)
{
 *this*=inverse(x);
 return *this;
}

ZZn8 inverse(const ZZn8& w)
{
    ZZn8 y=conj(w);
    ZZn4 u=w.a;
    ZZn4 v=w.b;
    u*=u;
    v*=v;
    u-=tx(v);
    u=inverse(u);
    y*=u;
    return y;
}

ZZn8 operator+(const ZZn8& x,const ZZn8& y) 
{ZZn8 w=x; w.a+=y.a; w.b+=y.b; return w; } 

ZZn8 operator+(const ZZn8& x,const ZZn4& y) 
{ZZn8 w=x; w.a+=y; return w; } 

ZZn8 operator+(const ZZn8& x,const ZZn& y) 
{ZZn8 w=x; w.a+=y; return w; } 

ZZn8 operator-(const ZZn8& x,const ZZn8& y) 
{ZZn8 w=x; w.a-=y.a; w.b-=y.b; return w; } 

ZZn8 operator-(const ZZn8& x,const ZZn4& y) 
{ZZn8 w=x; w.a-=y; return w; } 

ZZn8 operator-(const ZZn8& x,const ZZn& y) 
{ZZn8 w=x; w.a-=y; return w; } 

ZZn8 operator-(const ZZn8& x) 
{ZZn8 w; w.a=-x.a; w.b=-x.b; return w; } 

ZZn8 operator*(const ZZn8& x,const ZZn8& y)
{
 ZZn8 w=x;  
 if (&x==&y) w*=w;
 else        w*=y;  
 return w;
}

ZZn8 operator*(const ZZn8& x,const ZZn4& y)
{ZZn8 w=x; w*=y; return w;}

ZZn8 operator*(const ZZn8& x,const ZZn& y)
{ZZn8 w=x; w*=y; return w;}

ZZn8 operator*(const ZZn4& y,const ZZn8& x)
{ZZn8 w=x; w*=y; return w;}

ZZn8 operator*(const ZZn& y,const ZZn8& x)
{ZZn8 w=x; w*=y; return w;}

ZZn8 operator*(const ZZn8& x,int y)
{ZZn8 w=x; w*=y; return w;}

ZZn8 operator*(int y,const ZZn8& x)
{ZZn8 w=x; w*=y; return w;}

ZZn8 operator/(const ZZn8& x,const ZZn8& y)
{ZZn8 w=x; w/=y; return w;}

ZZn8 operator/(const ZZn8& x,const ZZn4& y)
{ZZn8 w=x; w/=y; return w;}

ZZn8 operator/(const ZZn8& x,const ZZn& y)
{ZZn8 w=x; w/=y; return w;}

ZZn8 operator/(const ZZn8& x,int i)
{ZZn8 w=x; w/=i; return w;}
#ifndef MR_NO_RAND
ZZn8 randn8(void)
{ZZn8 w; w.a=randn4(); w.b=randn4(); return w;}
#endif
BOOL qr(const ZZn8& x)
{
    ZZn4 a,s;
    int qnr=get_mip()->qnr;
    if (x.iszero()) return TRUE;
    if (x.b.iszero()) return TRUE;
    s=x.b; s*=s; 
    a=x.a; a*=a; a-=tx(s);
    if (!qr(a)) return FALSE;
    return TRUE;
/*
    s=sqrt(a);
    if (qr((x.a+s)/2) || qr((x.a-s)/2)) return TRUE;
    return FALSE;
*/
}

ZZn8 sqrt(const ZZn8& x)
{
// sqrt(a+xb) = sqrt(a+sqrt(a*a-n*b*b)/2)+x.b/(2*sqrt(a+sqrt(a*a-n*b*b)/2))
// where x*x=n

    ZZn8 w;
    ZZn4 a,s;
    if (x.iszero()) return w;

    if (x.b.iszero())
    {
        if (qr(x.a))
        {
            s=sqrt(x.a);
            w.a=s; w.b=0;
        }
        else
        {
            s=sqrt(txd(x.a));
            w.a=0; w.b=s;
        }
        return w;   
    }

    s=x.b; s*=s; 
    a=x.a; a*=a; a-=tx(s);

    s=sqrt(a);
    if (s.iszero()) return w;

    if (qr((x.a+s)/2))
    {
        a=sqrt((x.a+s)/2);
    }
    else
    {
        a=sqrt((x.a-s)/2);
        if (a.iszero()) return w;
    }

    w.a=a;
    w.b=x.b/(2*a);

    return w;
}

ZZn8 conj(const ZZn8& x)
{
    ZZn8 u=x;
    u.conj();
    return u;
}

ZZn8 tx(const ZZn8& x)
{
    ZZn4 t=tx(x.b);
    ZZn8 u(t,x.a);
    return u;
}

// regular ZZn8 powering - but see powl function in zzn4.h

ZZn8 pow(const ZZn8& x,const Big& k)
{
    int i,j,nb,n,nbw,nzs;
    ZZn8 u,u2,t[16];
    if (k==0) return (ZZn8)1;
    u=x;
    if (k==1) return u;
//
// Prepare table for windowing
//
    u2=(u*u);
    t[0]=u;
   
    for (i=1;i<16;i++)
        t[i]=u2*t[i-1];

// Left to right method - with windows

    nb=bits(k);
    if (nb>1) for (i=nb-2;i>=0;)
    {
        n=window(k,i,&nbw,&nzs,5);
        for (j=0;j<nbw;j++) u*=u;
        if (n>0) u*=t[n/2];
        i-=nbw;
        if (nzs)
        {
            for (j=0;j<nzs;j++) u*=u;
            i-=nzs;
        }
    }
    return u;
}

// standard MIRACL multi-exponentiation

ZZn8 pow(int n,const ZZn8* x,const Big* b)
{
    int k,j,i,m,nb,ea;
    ZZn8 *G;
    ZZn8 r;
    m=1<<n;
    G=new ZZn8[m];
    
    for (i=0,k=1;i<n;i++)
    {
        for (j=0; j < (1<<i) ;j++)
        {
            if (j==0)   G[k]=x[i];
            else        G[k]=G[j]*x[i];      
            k++;
        }
    }

    nb=0;
    for (j=0;j<n;j++) 
        if ((k=bits(b[j]))>nb) nb=k;

    r=1;
    for (i=nb-1;i>=0;i--) 
    {
        ea=0;
        k=1;
        for (j=0;j<n;j++)
        {
            if (bit(b[j],i)) ea+=k;
            k<<=1;
        }
        r*=r;
        if (ea!=0) r*=G[ea];
    }
    delete [] G;
    return r;
}

ZZn8 powl(const ZZn8& x,const Big& k)
{
    ZZn8 w8,w9,two,y;
    int i,nb;

    two=(ZZn)2;
    y=two*x;
    if (k==0)  return (ZZn8)two;
    if (k==1)  return y;

    w8=two;
    w9=y;
    nb=bits(k);
    for (i=nb-1;i>=0;i--)
    {
        if (bit(k,i))
        {
            w8*=w9; w8-=y; w9*=w9; w9-=two;
        }
        else
        {
            w9*=w8; w9-=y; w8*=w8; w8-=two;
        }
    }
    return (w8/2);
}

#ifndef MR_NO_STANDARD_IO

ostream& operator<<(ostream& s,const ZZn8& xx)
{
    ZZn8 b=xx;
    ZZn4 x,y;
    b.get(x,y);
    s << "[" << x << "," << y << "]";
    return s;    
}

#endif
