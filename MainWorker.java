package artesoft.scr.ferintegrationservice;

/**
 * Created by tkolomiets on 10.10.2016.
 */

import artesoft.common.BooleansStrings;
import artesoft.common.Utils;
import artesoft.scr.ferintegrationservice.db.Repository;
import artesoft.scr.ferintegrationservice.db.Statements;
import artesoft.scr.ferintegrationservice.ferclient.FerCaller;
import artesoft.scr.ferintegrationservice.ferclient.messages.constructors.*;
import oracle.jdbc.OracleTypes;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.CallableStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.*;

public class MainWorker implements Runnable {

    // Classes
    private class FerRequest {

        private int _id;
        private String _code;
        private long _baseRecordId;

        public long getBaseRecordId() {
            return _baseRecordId;
        }

        public int getId() {
            return _id;
        }

        public String getCode() {
            return _code;
        }

        public FerRequest(int id, String code, long baseRecordId) {

            _id = id;
            _code = code;
            _baseRecordId = baseRecordId;
        }
    }

    // Vars
    private static Logger _logger = LoggerFactory.getLogger(MainWorker.class);

    private boolean _shutdown = false;
    private boolean _sleeping = false;
    private boolean _stopped = false;

    private Map<String, FerCaller> _ferCallers = new HashMap<String, FerCaller>();
    private List<FerRequest> _ferProcessingRequests = new ArrayList<FerRequest>();

    // Getters/Setters

    public void setShutDown(boolean shutdown) {

        _shutdown = shutdown;
    }

    public boolean isSleeping() {
        return _sleeping;
    }

    public boolean isStopped() {
        return _stopped;
    }


    // Private methods

    private void loadFerCallers() {
        _ferCallers.put("AcceptAppointment", new AcceptAppointment());
        _ferCallers.put("ActivateQueue", new ActivateQueue());
        _ferCallers.put("CreateAppointment", new CreateAppointment());
        _ferCallers.put("CreateQueue", new CreateQueue());
        _ferCallers.put("CreateDoctor", new CreateDoctor());
        _ferCallers.put("CreateSchedule", new CreateSchedule());
        _ferCallers.put("DeactivateQueue", new DeactivateQueue());
        _ferCallers.put("DeclineAppointment", new DeclineAppointment());
        _ferCallers.put("DeleteAppointment", new DeleteAppointment());
        _ferCallers.put("DeleteDoctor", new DeleteDoctor());
        _ferCallers.put("DeleteQueue", new DeleteQueue());
        _ferCallers.put("DeleteSchedule", new DeleteSchedule());
        _ferCallers.put("RegisterPatientNotArrival", new RegisterPatientNotArrival());
        _ferCallers.put("RegisterServiceNotProvision", new RegisterServiceNotProvision());
        _ferCallers.put("RegisterPatientArrival", new RegisterPatientArrival());
        _ferCallers.put("RegisterServiceProvision", new RegisterServiceProvision());
        _ferCallers.put("RefuseAppointment", new RefuseAppointment());
        _ferCallers.put("ReserveAppointmentTime", new ReserveAppointmentTime());
        _ferCallers.put("UpdateDoctor", new UpdateDoctor());
        _ferCallers.put("UpdateQueue", new UpdateQueue());
        _ferCallers.put("UpdateSchedule", new UpdateSchedule());
    }


    // Public methods

    public void run() {

        _logger.info("Worker thread is started");

        loadFerCallers();

        CallableStatement gpr_stmt = null;
        CallableStatement sci_stmt = null;
        CallableStatement glr_stmt = null;
        CallableStatement slr_stmt = null;

        try {

            gpr_stmt = Repository.prepareCallable(Statements.GET_PENDING_REQUESTS);
            gpr_stmt.registerOutParameter(1, OracleTypes.CURSOR);

            sci_stmt = Repository.prepareCallable(Statements.SET_CALL_INFO);
            sci_stmt.registerOutParameter(1, OracleTypes.INTEGER);

            glr_stmt = Repository.prepareCallable(Statements.GET_UNHANDLED_LOG_RECORDS);
            glr_stmt.registerOutParameter(1, OracleTypes.CURSOR);

            slr_stmt = Repository.prepareCallable(Statements.SET_HANDLED_LOG_RECORDS);
            slr_stmt.registerOutParameter(1, OracleTypes.INTEGER);

            _logger.info("Main work cycle is started");

            // _shutDown will set to true from Server.stop() when Windows service will be shutting down
            while (!_shutdown) {

                _logger.info(String.format("Get pending requests"));

                gpr_stmt.execute();

                // Main work cycle based on db query, which gets all pending fer requests for next processing
                try (ResultSet all_pending_requests = (ResultSet) gpr_stmt.getObject(1)) {

                    while (all_pending_requests.next()) {

                        // Get current pending request
                        int operationId = all_pending_requests.getInt("id");
                        String operationCode = all_pending_requests.getString("code");
                        int recordId = all_pending_requests.getInt("base_record_id");

                        _ferProcessingRequests.add(new FerRequest(operationId, operationCode, recordId));
                    }
                }

                _logger.info(String.format("Pending requests are get: %d", _ferProcessingRequests.size()));

                for (int i = 0; i < _ferProcessingRequests.size(); i++) {

                    FerRequest req = _ferProcessingRequests.get(i);

                    String requestInfo = String.format("(%d from %d): id=%d, code=%s",
                            i + 1, _ferProcessingRequests.size(), req.getId(), req.getCode());

                    sci_stmt.setInt(2, req.getId());

                    try {

                        FerCaller caller = _ferCallers.get(req.getCode());

                        if (caller == null) {
                            throw new FerException(String.format("Request code not exists %s", requestInfo));
                        }

                        _logger.info(String.format("Remote call starting: %s", requestInfo));

                        // Set start db data endpoint for request. It can be record in table, which can then join with other db table, etc.
                        // Call remote fer service..
                        caller.call(req.getId(), req.getBaseRecordId());

                        sci_stmt.setString(3, BooleansStrings.True);
                        sci_stmt.setString(4, BooleansStrings.True);
                        sci_stmt.execute();

                        _logger.info(String.format("Remote call completed successfully: %s", requestInfo));


                    } catch (Exception e) {

                        _logger.error(String.format("Remote call completed failed: %s", requestInfo));

                        sci_stmt.setString(3, BooleansStrings.False);
                        sci_stmt.setNull(4, java.sql.Types.VARCHAR);
                        sci_stmt.execute();
                    }
                }

                // Clear processed messages for next work cycle
                _ferProcessingRequests.clear();

                // db exceptions log

                _logger.info("DB system log");

                String handled_log_records = "";
                glr_stmt.execute();

                try (ResultSet unhandled_log_records = (ResultSet) glr_stmt.getObject(1)) {

                    while (unhandled_log_records.next()) {

                        _logger.error(String.format("DB system log exception: Created = %s, Operation = %s, Message = %s",
                                unhandled_log_records.getString("created"),
                                unhandled_log_records.getString("operation"),
                                unhandled_log_records.getString("message")
                        ));

                        handled_log_records = String.format("%s,%d", handled_log_records, unhandled_log_records.getInt("id"));
                    }
                }

                // Clear logged db exceptions records in db log
                if (StringUtils.isNotBlank(handled_log_records)) {

                    handled_log_records.replaceFirst(",", "");
                    slr_stmt.setString(2, handled_log_records);
                    slr_stmt.execute();
                }

                _sleeping = true;

                _logger.info(String.format("Main work cycle is sleeping %d sec", Config.WORK_CYCLE_SLEEPING));

                Thread.sleep(Config.WORK_CYCLE_SLEEPING * 1000);

                _sleeping = false;
            }
        } catch (Exception e) {
            _logger.error(Utils.getExceptionStackTrace(e));
        }

        try {

            _logger.info("Close work cycle db cursors");

            if (gpr_stmt != null && !gpr_stmt.isClosed())
                gpr_stmt.close();

            if (sci_stmt != null && !sci_stmt.isClosed())
                sci_stmt.close();

            if (glr_stmt != null && !glr_stmt.isClosed())
                glr_stmt.close();

            if (slr_stmt != null && !slr_stmt.isClosed())
                slr_stmt.close();

        } catch (Exception e) {
            _logger.error(Utils.getExceptionStackTrace(e));
        }

        _logger.info("Main work cycle is stopped correctly");

        // Notice Server.stop() about thread has shut down
        _stopped = true;
    }


}
