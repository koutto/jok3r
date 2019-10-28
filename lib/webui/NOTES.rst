

apt-get update
apt-get install nodejs 

apt-get install npm
npm -v => 5.8.0
npm install npm@latest -g
--
curl https://www.npmjs.com/install.sh | sudo sh
npm -v => 6.12.0

---
npm install -g create-react-app
create-react-app frontend
cd frontend/
.. npm install typescript
.. npm install react-admin ra-data-json-server prop-types
npm start


Sublime:
Tools > Install Package Control
Preferences > Package Control
	Install Package: Babel, Babel snipper



git clone https://github.com/flatlogic/react-material-admin.git frontend
cd frontend/

npm install typescript
npm install @material-ui/core
npm install @material-ui/icons
npm install
npm start


---

Styles
======
npm install @material-ui/styles

https://material-ui.com/styles/basics/

import React from 'react';
import { makeStyles } from '@material-ui/styles';
import Button from '@material-ui/core/Button';

const useStyles = makeStyles({
  root: {
    background: 'linear-gradient(45deg, #FE6B8B 30%, #FF8E53 90%)',
    border: 0,
    borderRadius: 3,
    boxShadow: '0 3px 5px 2px rgba(255, 105, 135, .3)',
    color: 'white',
    height: 48,
    padding: '0 30px',
  },
});

export default function Hook() {
  const classes = useStyles();
  return <Button className={classes.root}>Hook</Button>;
}