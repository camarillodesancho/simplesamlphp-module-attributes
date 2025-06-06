# Hub & Spoke: TargetedID

A flexible way for generate one or more values for the
eduPersonTargetedId attribute.

## Configuration samples


### eduPersonTargetedId with one unique standard value:

```php
    'authproc' => array(
        50 => 'hubandspoke:TargetedID',
    ),

    => sha256(userID + '@@' + targetID + '@@' + sourceID)
```

### eduPersonTargetedId obfuscated with a salt:

```php
    'authproc' => array(
        50 => array(
            'class' => 'hubandspoke:TargetedID',
            'salt'  => 'randomString',
        ),
    ),

    => sha256(salt + '@@' + userID + '@@' + targetID + '@@' + sourceID + '@@' + salt)
```

### eduPersonTargetedId with a different formula:

```php
    'authproc' => array(
        50 => array(
            'class'  => 'hubandspoke:TargetedID',
            'userID' => 'Attributes/mail',
            'fields' => array('salt', 'userID', 'targetID'),
            'salt'   => 'randomString',
        ),
    ),

    => sha256(salt + '@@' + mail + '@@' + targetID)
```    

### eduPersonTargetedId with two values:

```php
    'authproc' => array(
        50 => array(
            'class'  => 'hubandspoke:TargetedID',
            'salt'   => 'randomString',
            'values' => array(
                'new' => array(
                    'fieldSeparator' => '//',
                ),
                'old' => array(
                    'hashFunction' => 'md5',
                    'fields'       => array('userID'),
                ),
            ),
        ),
    ),

    => sha256(salt + '//' + userID + '//' + targetID + '//' + sourceID + '//' + salt)
    => md5(userID)
```    

### eduPersonTargetedId with two values prefixed:
    - one of them only for a specific SP (http://*.example.com)
    - the other one for all SP, but considering the same SP
      all URL https://*.blogs.example.com (same eduPersonTargetedId)

```php
    'authproc' => array(
        50 => array(
            'class'  => 'hubandspoke:TargetedID',
            'salt'   => 'randomString',
            'values' => array(
                'new' => array(
                    'prefix'          => '{new}',
                    'targetTransform' => array(
                        '#^(https?://)[^./]+\.(blogs\.example\.com)(/|$).*$#' => '$1$2/',
                    ),
                ),
                'old' => array(
                    'prefix'       => '{old}',
                    'hashFunction' => 'md5',
                    'userID'       => array('Attributes/mail', 'UserID'),
                    'fields'       => 'userID',
                    'ifTarget'     => '#^https?://([^./]+\.)*example\.com(/|$)#',
                ),
            ),
        ),
    ),

    => '{new}' + sha256(salt + '@@' + userID + '@@' + targetID* + '@@' + sourceID + '@@' + salt)
    => '{old}' + md5(userID) only for *.example.com
```

## Description

hubandspoke:TargetedID is an Authentication Processing Filter for SimpleSAMLphp
(https://simplesamlphp.org/docs/stable/simplesamlphp-authproc).

Based on core:TargetedID (by Olav Morken, UNINETT AS), it allows:

    - generate one or more values for the eduPersonTargetdId attribute
    - feed the values with user, source and/or destination identifiers
    - use any of the hash algorithms supported by PHP
    - generate some values only for selected users/destinations
    - processing destination identifiers before using them
    - add a prefix for further processing
    - avoid dependencies (all configuration is contained at IdP level)


## Configuration

The best place to configure this filter is in the saml20-idp-hosted file. Thus,
if you move the IdP to another SSP instance, the eduPersonTargetedId obtained
will not change.

There are 3 levels of configuration:

1. **defaults**: parameters hard-coded at module
2. **filter**: parameters set at first level on configuration file
3. **value**: parameters set inside the 'values' switch

For each value of the eduPersonTargetedId attribute, these configurations are
applied in order, so 'defaults' has the lowest priority and 'value' has the
highest priority. If a parameter is not set on a level, it inherits the value
of previous levels.

Configuration is based on the following parameters:

| Parámetro | Descripción |
|-----------|-------------|
| userID | Array of attributes (in order of preference) for identify the user. It's the most important parameter to obtain a quality eduPersonTargetedId attribute. |
| ifUser | Array of regular expressions to check the user identifier. Only users matching one of these patterns will obtain the value generated. |
| targetID | Array of attributes (in order of preference) for identify the target. On Hub & Spoke federations the target would be the SP, not the hub. |
| targetTransform | Array of transformations to apply to a target identifier. It allows uniform process of a same SP with different URL entries. Keys are regular expressions and Values are string replacements (following the preg_replace syntax) |
| ifTarget | Array of regular expressions to check the target identifier. Only targets matching one of these patterns will obtain the value generated. This check is applied after transformations, if any. |
| sourceID | List of attributes (in order of preference) for identify the ource. |
| salt | A random string to add entropy to the generated values. |
| hashFunction | The hash function used to obtain an opaque attribute. |
| fields | Array of fields to combine to generate each value. Each field has to be a parameter of the configuration (userID, targetID...). A field can be inserted more than one time. |
| fieldSeparator |   The string used to glue all the fields. |
| prefix | A string that will be prefixed to the hash value obtained. On Hub & Spoke federations it allows further processing of the attribute (on the hub). |
| nameId | A boolean indicating if we want SAML 2.0 name identifier elements. |
| values | Array of specific configurations, one for each value of the ttribute. If this switch is omitted, an unique value will be generated. Parameters on this array override generic parameters. |
 
 

For parameters containing a single value, you can write directly a string,
instead of an array with that only value.

The filter can search on all the attributes set after authentication (SSP state).
When more than one level is used, the character '/' sets the level change:

```php
  'core:SP'           references to    state['core:SP']
  'Attributes/uid'    references to    state['Attributes']['uid']
```


### Default values

```php
    userID:          'UserID'
    ifUser:          NULL
    targetID:        array('saml:RequesterID', 'core:SP')
    targetTransform: NULL
    ifTarget:        NULL
    sourceID:        array('Attributes/schacHomeOrganization', 'core:IdP')
    salt:            NULL
    hashFunction:    'sha256'
    fields:          array('salt', 'userID', 'targetID', 'sourceID', 'salt')
    fieldSeparator:  '@@'
    prefix:          NULL
    nameId:          false
```

## Contenido directorio modulo hubandspoke
```bash
hubandspoke
├── composer.json
├── docs
│   └── TargetedID.md
└── src
    └── Auth
        └── Process
            └── TargetedID.php
```
