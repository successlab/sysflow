package sysflow_controller.timer;

import java.time.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sysflow_controller.core.SFChannelHandler;
import sysflow_controller.message.FlowModMessage;
import sysflow_controller.types.sf_host;

//install flow rules at a specific time
//TODO: support more hosts and more flow mod messages

// kevin, current implementation executes infinitely without proper schedule
/*
public class sf_timer
{
    ScheduledExecutorService executorService = Executors.newScheduledThreadPool(1);
    
    sf_host host;
    FlowModMessage flowmod;
    
    volatile boolean isStopIssued;
    

    public sf_timer(sf_host h, FlowModMessage msg) 
    {
    	this.host = h;
    	this.flowmod = msg;
    }

    public void startExecutionAt(int targetHour, int targetMin, int targetSec)
    {
        Runnable taskWrapper = new Runnable(){

            @Override
            public void run() 
            {
            	//host.sendMsg(flowmod);
            	
            	System.out.println("Timer fired");
                startExecutionAt(targetHour, targetMin, targetSec);
            }	

        };
        long delay = computeNextDelay(targetHour, targetMin, targetSec);
        executorService.schedule(taskWrapper, delay, TimeUnit.SECONDS);
    }

    private long computeNextDelay(int targetHour, int targetMin, int targetSec) 
    {
        LocalDateTime localNow = LocalDateTime.now();
        ZoneId currentZone = ZoneId.systemDefault();
        ZonedDateTime zonedNow = ZonedDateTime.of(localNow, currentZone);
        ZonedDateTime zonedNextTarget = zonedNow.withHour(targetHour).withMinute(targetMin).withSecond(targetSec);
        if(zonedNow.compareTo(zonedNextTarget) > 0)
            zonedNextTarget = zonedNextTarget.plusDays(1);

        Duration duration = Duration.between(zonedNow, zonedNextTarget);
        return duration.getSeconds();
    }

    public void stop()
    {
        executorService.shutdown();
        try {
            executorService.awaitTermination(1, TimeUnit.DAYS);
        } catch (InterruptedException ex) {
            //
        }
    }
}
*/

// kevin, this timer is designed to run per day periodically
public class sf_timer
{

	private static final Logger LOG = LoggerFactory
			.getLogger(sf_timer.class);
    private ScheduledExecutorService executorService = Executors.newScheduledThreadPool(1);

    private String name;
    sf_host host;
    FlowModMessage flowmod;

    private int targetHour;
    private int targetMin;
    private int targetSec;

    private volatile boolean isBusy = false;
    private volatile boolean isFired = false;
    private volatile ScheduledFuture<?> scheduledTask = null;

    private AtomicInteger completedTasks = new AtomicInteger(0);

    //--------------------------------------------------------------
    
    
    public sf_timer(String execName, sf_host h, FlowModMessage msg) 
    {
    	this.name = "ScheduledExecutor [" + execName + "]";
    	
    	this.host = h;
    	this.flowmod = msg;
    }
    
    public void startExecutionAt(int targetHour, int targetMin, int targetSec)
    {
    	this.targetHour = targetHour;
        this.targetMin = targetMin;
        this.targetSec = targetSec;
        
        scheduleNextTask(doTaskWork());
    }

    private Runnable doTaskWork() {
        return () -> {
            //LOG.info(name + " [" + completedTasks.get() + "] start: " + curZonedDateTime());
            try {
            	ZonedDateTime zonedNow = curZonedDateTime();
                ZonedDateTime zonedNextTarget = zonedNow.withHour(targetHour).withMinute(targetMin).withSecond(targetSec).withNano(0);
                
                isBusy = true;
   
                if (zonedNow.compareTo(zonedNextTarget) > 0) {
                	LOG.info(name + " Scheduled FlowMod installation at " + curZonedDateTime());
                	host.sendMsg(flowmod);
                }
                
                
            } catch (Exception ex) {
                LOG.error(name + " throw exception in " + curZonedDateTime(), ex);
            } finally {
                isBusy = false;
            }
            scheduleNextTask(doTaskWork());
            //LOG.info(name + " [" + completedTasks.get() + "] finish: " + curZonedDateTime());
            //LOG.info(name + " completed tasks: " + completedTasks.incrementAndGet());
        };
    }

    private void scheduleNextTask(Runnable task) {
        //LOG.info(name + " Current schedule at " + curZonedDateTime());
        long delay = computeNextDelay(targetHour, targetMin, targetSec);
        //LOG.info(name + " has delay in " + delay);
        
        scheduledTask = executorService.schedule(task, delay, TimeUnit.SECONDS);
    }

    private long computeNextDelay(int targetHour, int targetMin, int targetSec) {
        ZonedDateTime zonedNow = curZonedDateTime();
        ZonedDateTime zonedNextTarget = zonedNow.withHour(targetHour).withMinute(targetMin).withSecond(targetSec).withNano(0);
        
        //LOG.info("zonedNow : " + zonedNow);
        //LOG.info("zonedNext: " + zonedNextTarget);
        ///LOG.info("Compare: " + zonedNow.compareTo(zonedNextTarget));
        
        if (zonedNow.compareTo(zonedNextTarget) > 0) {
            zonedNextTarget = zonedNextTarget.plusDays(1);	// executes per day
            LOG.info(name + " Next schedule at " + zonedNextTarget);
        }
        
        //LOG.info(name + " Next schedule at " + zonedNextTarget);
        
        Duration duration = Duration.between(zonedNow, zonedNextTarget);
        return duration.getSeconds();
    }

    // current zone id
    public static ZonedDateTime curZonedDateTime() {
        
        LocalDateTime localNow = LocalDateTime.now();
        ZoneId currentZone = ZoneId.systemDefault();
        ZonedDateTime zonedNow = ZonedDateTime.of(localNow, currentZone);
        
        return zonedNow;
    }

    public void stop() {
        LOG.info(name + " is stopping.");
        if (scheduledTask != null) {
            scheduledTask.cancel(false);
        }
        executorService.shutdown();
        LOG.info(name + " stopped.");
        try {
            LOG.info(name + " awaitTermination, start: isBusy [ " + isBusy + "]");
            // wait one minute to termination if busy
            if (isBusy) {
                executorService.awaitTermination(1, TimeUnit.MINUTES);
            }
        } catch (InterruptedException ex) {
            LOG.error(name + " awaitTermination exception", ex);
        } finally {
            LOG.info(name + " awaitTermination, finish");
        }
    }
}