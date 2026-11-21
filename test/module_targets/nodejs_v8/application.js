'use strict';

// An ordinary active Node program. The real legacy debugger supplies the API;
// the timer also exercises documented versions that wait for event-loop activity.
require('fs').writeFileSync('/tmp/module-target-nodejs-foreign', 'Preserve this unrelated file.\n');
setInterval(function () {}, 100);
