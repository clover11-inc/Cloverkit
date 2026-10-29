"""Compact shared unit labels; original values/units remain in saved evidence."""
UNITS={'revolutions_per_minute':'rpm','rpm':'rpm','kilometer_per_hour':'km/h','kph':'km/h',
       'degree_Celsius':'°C','celsius':'°C','percent':'%','volt':'V','kilopascal':'kPa',
       'gram / second':'g/s','grams_per_second':'g/s','second':'s','minute':'min',
       'liter / hour':'L/h','kilometer':'km','degree':'°','ratio':''}

def compact(value,unit=''):
    if type(value) in (int,float):value=f'{value:.1f}'.removesuffix('.0')
    return str(value)+' '+UNITS.get(unit,unit)
